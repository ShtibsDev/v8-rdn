// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// RDN parser — recursive descent parser producing V8 internal objects directly.
// Optimization techniques ported from json-parser.cc:
// - GC epilogue callback for pointer relocation (correctness fix)
// - Token lookup table for O(1) value dispatch
// - std::find_if whitespace skip (auto-vectorizable)
// - Smi-first number parsing (avoids strtod for small integers)
// - Deferred string materialization via ScanRdnString/MakeString
// - Object construction via ObjectLiteralMapFromCache + internalized keys
// - Array ElementsKind selection (PACKED_SMI / PACKED_DOUBLE / PACKED_ELEMENTS)
// - HandleScope per nesting level
// - HighAllocationThroughputScope at entry

#include "src/json/rdn-parser.h"

#include "src/base/small-vector.h"
#include "src/base/strings.h"
#include "src/common/assert-scope.h"
#include "src/common/globals.h"
#include "src/common/high-allocation-throughput-scope.h"
#include "src/date/date.h"
#include "src/execution/isolate.h"
#include "src/heap/factory.h"
#include "src/numbers/conversions.h"
#include "src/objects/bigint.h"
#include "src/objects/elements-kind.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/js-collection-inl.h"
#include "src/objects/js-objects.h"
#include "src/objects/js-regexp.h"
#include "src/objects/objects-inl.h"
#include "src/objects/ordered-hash-table.h"
#include "src/objects/string.h"
#include "src/objects/descriptor-array-inl.h"
#include "src/objects/field-type.h"
#include "src/objects/map-updater.h"
#include "src/objects/transitions.h"
#include "src/strings/char-predicates-inl.h"
#include "src/utils/boxed-float.h"

namespace v8 {
namespace internal {

namespace {

// ── RDN Token type for value dispatch ─────────────────────────────
enum class RdnToken : uint8_t {
  NUMBER,
  STRING,
  LBRACE,
  RBRACE,
  LBRACK,
  RBRACK,
  LPAREN,
  RPAREN,
  TRUE_LITERAL,
  FALSE_LITERAL,
  NULL_LITERAL,
  NAN_LITERAL,
  INFINITY_LITERAL,
  DATETIME,
  REGEX,
  MAP_KEYWORD,
  SET_KEYWORD,
  BINARY_B64,
  BINARY_HEX,
  WHITESPACE,
  COLON,
  COMMA,
  ILLEGAL,
  EOS
};

// ── Token lookup table (256-entry, constexpr) ─────────────────────
// Replaces the 18-deep if/else chain in ParseValue with O(1) dispatch.
// Reference: json-parser.cc:38-69
constexpr RdnToken GetOneCharRdnToken(uint8_t c) {
  // clang-format off
  return
     c == '"' ? RdnToken::STRING :
     IsDecimalDigit(c) ?  RdnToken::NUMBER :
     c == '-' ? RdnToken::NUMBER :
     c == '[' ? RdnToken::LBRACK :
     c == '{' ? RdnToken::LBRACE :
     c == ']' ? RdnToken::RBRACK :
     c == '}' ? RdnToken::RBRACE :
     c == '(' ? RdnToken::LPAREN :
     c == ')' ? RdnToken::RPAREN :
     c == 't' ? RdnToken::TRUE_LITERAL :
     c == 'f' ? RdnToken::FALSE_LITERAL :
     c == 'n' ? RdnToken::NULL_LITERAL :
     c == 'N' ? RdnToken::NAN_LITERAL :
     c == 'I' ? RdnToken::INFINITY_LITERAL :
     c == '@' ? RdnToken::DATETIME :
     c == '/' ? RdnToken::REGEX :
     c == 'M' ? RdnToken::MAP_KEYWORD :
     c == 'S' ? RdnToken::SET_KEYWORD :
     c == 'b' ? RdnToken::BINARY_B64 :
     c == 'x' ? RdnToken::BINARY_HEX :
     c == ' ' ? RdnToken::WHITESPACE :
     c == '\t' ? RdnToken::WHITESPACE :
     c == '\r' ? RdnToken::WHITESPACE :
     c == '\n' ? RdnToken::WHITESPACE :
     c == ':' ? RdnToken::COLON :
     c == ',' ? RdnToken::COMMA :
     RdnToken::ILLEGAL;
  // clang-format on
}

static const constexpr RdnToken one_char_rdn_tokens[256] = {
#define CALL_GET_TOKEN(N) GetOneCharRdnToken(N),
    INT_0_TO_127_LIST(CALL_GET_TOKEN)
#undef CALL_GET_TOKEN
#define CALL_GET_TOKEN(N) GetOneCharRdnToken(128 + N),
        INT_0_TO_127_LIST(CALL_GET_TOKEN)
#undef CALL_GET_TOKEN
};

// ── Scan flags for string scanning ────────────────────────────────
// Identical to JSON string escape rules. Used by ScanRdnString for
// vectorizable scanning via std::find_if + MayTerminateStringField.
// Reference: json-parser.cc:71-131

enum class EscapeKind : uint8_t {
  kIllegal,
  kSelf,
  kBackspace,
  kTab,
  kNewLine,
  kFormFeed,
  kCarriageReturn,
  kUnicode
};

using EscapeKindField = base::BitField8<EscapeKind, 0, 3>;
using MayTerminateStringField = EscapeKindField::Next<bool, 1>;
using NumberPartField = MayTerminateStringField::Next<bool, 1>;

constexpr bool MayTerminateRdnString(uint8_t flags) {
  return MayTerminateStringField::decode(flags);
}

constexpr EscapeKind GetEscapeKind(uint8_t flags) {
  return EscapeKindField::decode(flags);
}

constexpr bool IsNumberPart(uint8_t flags) {
  return NumberPartField::decode(flags);
}

constexpr uint8_t GetRdnScanFlags(uint8_t c) {
  // clang-format off
  return (c == 'b' ? EscapeKindField::encode(EscapeKind::kBackspace)
          : c == 't' ? EscapeKindField::encode(EscapeKind::kTab)
          : c == 'n' ? EscapeKindField::encode(EscapeKind::kNewLine)
          : c == 'f' ? EscapeKindField::encode(EscapeKind::kFormFeed)
          : c == 'r' ? EscapeKindField::encode(EscapeKind::kCarriageReturn)
          : c == 'u' ? EscapeKindField::encode(EscapeKind::kUnicode)
          : c == '"' ? EscapeKindField::encode(EscapeKind::kSelf)
          : c == '\\' ? EscapeKindField::encode(EscapeKind::kSelf)
          : c == '/' ? EscapeKindField::encode(EscapeKind::kSelf)
          : EscapeKindField::encode(EscapeKind::kIllegal)) |
         (c < 0x20 ? MayTerminateStringField::encode(true)
          : c == '"' ? MayTerminateStringField::encode(true)
          : c == '\\' ? MayTerminateStringField::encode(true)
          : MayTerminateStringField::encode(false)) |
         NumberPartField::encode(c == '.' ||
                                 c == 'e' ||
                                 c == 'E' ||
                                 IsDecimalDigit(c) ||
                                 c == '-' ||
                                 c == '+');
  // clang-format on
}

static const constexpr uint8_t character_rdn_scan_flags[256] = {
#define CALL_GET_SCAN_FLAGS(N) GetRdnScanFlags(N),
    INT_0_TO_127_LIST(CALL_GET_SCAN_FLAGS)
#undef CALL_GET_SCAN_FLAGS
#define CALL_GET_SCAN_FLAGS(N) GetRdnScanFlags(128 + N),
        INT_0_TO_127_LIST(CALL_GET_SCAN_FLAGS)
#undef CALL_GET_SCAN_FLAGS
};

template <typename Char>
RdnToken GetTokenForChar(Char c) {
  return V8_LIKELY(c <= unibrow::Latin1::kMaxChar) ? one_char_rdn_tokens[c]
                                                   : RdnToken::ILLEGAL;
}

template <typename Char>
bool Matches(base::Vector<const Char> chars, DirectHandle<String> string) {
  DCHECK(!string.is_null());
  return string->IsEqualTo(chars);
}

// ── GetFastKeyChars — extract raw bytes from internalized one-byte key ────
// Ported from json-parser.cc:1565-1590.
const uint8_t* GetFastKeyChars(Isolate* isolate, Tagged<String> key,
                               Tagged<Map> map,
                               const DisallowGarbageCollection& no_gc) {
  DCHECK(InstanceTypeChecker::IsOneByteString(map));
#if V8_STATIC_ROOTS_BOOL
  ReadOnlyRoots roots(isolate);
  if (map == roots.internalized_one_byte_string_map()) {
    return Cast<SeqOneByteString>(key)->GetChars(no_gc);
  } else {
    DCHECK(map == roots.external_internalized_one_byte_string_map() ||
           map == roots.uncached_external_internalized_one_byte_string_map());
    return Cast<ExternalOneByteString>(key)->GetChars();
  }
#else
  InstanceType instance_type = map->instance_type();
  switch (instance_type) {
    case INTERNALIZED_ONE_BYTE_STRING_TYPE:
      return Cast<SeqOneByteString>(key)->GetChars(no_gc);
    case EXTERNAL_INTERNALIZED_ONE_BYTE_STRING_TYPE:
    case UNCACHED_EXTERNAL_INTERNALIZED_ONE_BYTE_STRING_TYPE:
      return Cast<ExternalOneByteString>(key)->GetChars();
    default:
      UNREACHABLE();
  }
#endif
}

// ── Folded mutable HeapNumber helpers ──────────────────────────────
// Copied from json-parser.cc:696-762 to avoid modifying upstream code.

class FoldedMutableHeapNumberAllocation {
 public:
  static_assert(!USE_ALLOCATION_ALIGNMENT_HEAP_NUMBER_BOOL);

  FoldedMutableHeapNumberAllocation(Isolate* isolate, int count) {
    if (count == 0) return;
    int size = count * sizeof(HeapNumber);
    raw_bytes_ = isolate->factory()->NewByteArray(size);
  }

  Handle<ByteArray> raw_bytes() const { return raw_bytes_; }

 private:
  Handle<ByteArray> raw_bytes_ = {};
};

class FoldedMutableHeapNumberAllocator {
 public:
  FoldedMutableHeapNumberAllocator(
      Isolate* isolate, FoldedMutableHeapNumberAllocation* allocation,
      DisallowGarbageCollection& no_gc)
      : isolate_(isolate), roots_(isolate) {
    if (allocation->raw_bytes().is_null()) return;

    raw_bytes_ = allocation->raw_bytes();
    mutable_double_address_ =
        reinterpret_cast<Address>(allocation->raw_bytes()->begin());
  }

  ~FoldedMutableHeapNumberAllocator() {
    if (mutable_double_address_ == 0) {
      DCHECK(raw_bytes_.is_null());
      return;
    }

    DCHECK_EQ(mutable_double_address_,
              reinterpret_cast<Address>(raw_bytes_->end()));
    isolate_->heap()->EnsureSweepingCompletedForObject(*raw_bytes_);
    raw_bytes_->set_length(0);
  }

  Tagged<HeapNumber> AllocateNext(ReadOnlyRoots roots, Float64 value) {
    DCHECK_GE(mutable_double_address_,
              reinterpret_cast<Address>(raw_bytes_->begin()));
    Tagged<HeapObject> hn = HeapObject::FromAddress(mutable_double_address_);
    hn->set_map_after_allocation(isolate_, roots.heap_number_map());
    Cast<HeapNumber>(hn)->set_value_as_bits(value.get_bits());
    mutable_double_address_ +=
        ALIGN_TO_ALLOCATION_ALIGNMENT(sizeof(HeapNumber));
    DCHECK_LE(mutable_double_address_,
              reinterpret_cast<Address>(raw_bytes_->end()));
    return Cast<HeapNumber>(hn);
  }

 private:
  Isolate* isolate_;
  ReadOnlyRoots roots_;
  Handle<ByteArray> raw_bytes_ = {};
  Address mutable_double_address_ = 0;
};

// ── RdnDataObjectBuilder ──────────────────────────────────────────
// Copied from json-parser.cc:764-1271 (JSDataObjectBuilder), renamed to
// avoid ODR conflicts. Builds data objects via pre-computed map transitions
// and single-pass field writes — the key optimization for closing the
// JSON.parse performance gap.
class RdnDataObjectBuilder {
 public:
  enum HeapNumberMode {
    kNormalHeapNumbers,
    kHeapNumbersGuaranteedUniquelyOwned
  };
  RdnDataObjectBuilder(Isolate* isolate, ElementsKind elements_kind,
                        int expected_named_properties,
                        DirectHandle<Map> expected_final_map,
                        HeapNumberMode heap_number_mode)
      : isolate_(isolate),
        elements_kind_(elements_kind),
        expected_property_count_(expected_named_properties),
        heap_number_mode_(heap_number_mode),
        expected_final_map_(expected_final_map) {
    if (!TryInitializeMapFromExpectedFinalMap()) {
      InitializeMapFromZero();
    }
  }

  template <typename PropertyIterator>
  Handle<JSObject> BuildFromIterator(
      PropertyIterator&& it, MaybeHandle<FixedArrayBase> maybe_elements = {}) {
    Handle<String> failed_property_add_key;
    for (; !it.Done(); it.Advance()) {
      Handle<String> property_key;
      if (!TryAddFastPropertyForValue(
              it.GetKeyChars(),
              [&](Handle<String> expected_key) {
                return property_key = it.GetKey(expected_key);
              },
              [&]() { return it.GetValue(true); })) {
        failed_property_add_key = property_key;
        break;
      }
    }

    DirectHandle<FixedArrayBase> elements;
    if (!maybe_elements.ToHandle(&elements)) {
      elements = isolate_->factory()->empty_fixed_array();
    }
    CreateAndInitialiseObject(it.RevisitValues(), elements);

    for (; !it.Done(); it.Advance()) {
      DirectHandle<String> key;
      if (!failed_property_add_key.is_null()) {
        key = std::exchange(failed_property_add_key, {});
      } else {
        key = it.GetKey({});
      }
#ifdef DEBUG
      uint32_t index;
      DCHECK(!key->AsArrayIndex(&index));
#endif
      Handle<Object> value = it.GetValue(false);
      AddSlowProperty(key, value);
    }

    return object();
  }

  template <typename Char, typename GetKeyFunction, typename GetValueFunction>
  V8_INLINE bool TryAddFastPropertyForValue(base::Vector<const Char> key_chars,
                                            GetKeyFunction&& get_key,
                                            GetValueFunction&& get_value) {
    DCHECK(object_.is_null());

    Handle<String> key;
    bool existing_map_found =
        TryFastTransitionToPropertyKey(key_chars, get_key, &key);
    DirectHandle<Object> value = get_value();
    if (existing_map_found) {
      if (!TryGeneralizeFieldToValue(value)) {
        return false;
      }
      AdvanceToNextProperty();
      return true;
    }

    Tagged<DescriptorArray> descriptors = map_->instance_descriptors(isolate_);
    InternalIndex descriptor_number =
        descriptors->SearchWithCache(isolate_, *key, *map_);
    if (descriptor_number.is_found()) {
      return false;
    }

    if (!TransitionsAccessor::CanHaveMoreTransitions(isolate_, map_)) {
      return false;
    }

    Representation representation =
        Object::OptimalRepresentation(*value, isolate_);
    DirectHandle<FieldType> type =
        Object::OptimalType(*value, isolate_, representation);
    MaybeHandle<Map> maybe_map = Map::CopyWithField(
        isolate_, map_, key, type, NONE, PropertyConstness::kConst,
        representation, INSERT_TRANSITION);
    Handle<Map> next_map;
    if (!maybe_map.ToHandle(&next_map)) return false;
    if (next_map->is_dictionary_map()) return false;

    map_ = next_map;
    if (representation.IsDouble()) {
      RegisterFieldNeedsFreshHeapNumber(value);
    }
    AdvanceToNextProperty();
    return true;
  }

  template <typename ValueIterator>
  V8_INLINE void CreateAndInitialiseObject(
      ValueIterator value_it, DirectHandle<FixedArrayBase> elements) {
    DCHECK(object_.is_null());

    if (current_property_index_ < property_count_in_expected_final_map_) {
      RewindExpectedFinalMapFastPathToBeforeCurrent();
    }

    if (map_->is_dictionary_map()) {
      DCHECK_EQ(current_property_index_, 0);

      Handle<JSObject> object = isolate_->factory()->NewSlowJSObjectFromMap(
          map_, expected_property_count_);
      object->set_elements(*elements);
      object_ = object;
      return;
    }

    DCHECK_EQ(current_property_index_, map_->NumberOfOwnDescriptors());
    DCHECK_EQ(current_property_index_,
              map_->GetInObjectProperties() - map_->UnusedInObjectProperties());

    FoldedMutableHeapNumberAllocation hn_allocation(isolate_,
                                                    extra_heap_numbers_needed_);

    Handle<JSObject> object = isolate_->factory()->NewJSObjectFromMap(
        map_, AllocationType::kYoung, DirectHandle<AllocationSite>::null(),
        NewJSObjectType::kNoEmbedderFieldsAndNoApiWrapper);
    DisallowGarbageCollection no_gc;
    Tagged<JSObject> raw_object = *object;

    raw_object->set_elements(*elements);
    Tagged<DescriptorArray> descriptors =
        raw_object->map()->instance_descriptors();

    FoldedMutableHeapNumberAllocator hn_allocator(isolate_, &hn_allocation,
                                                  no_gc);

    ReadOnlyRoots roots(isolate_);

    int current_property_offset = raw_object->GetInObjectPropertyOffset(0);
    for (int i = 0; i < current_property_index_; ++i, ++value_it) {
      InternalIndex descriptor_index(i);
      Tagged<Object> value = **value_it;

      if (heap_number_mode_ != kHeapNumbersGuaranteedUniquelyOwned ||
          IsSmi(value)) {
        PropertyDetails details = descriptors->GetDetails(descriptor_index);
        if (details.representation().IsDouble()) {
          value = hn_allocator.AllocateNext(
              roots, Float64(Object::NumberValue(value)));
        }
      }

      DCHECK(FieldIndex::ForPropertyIndex(object->map(), i).is_inobject());
      DCHECK_EQ(current_property_offset,
                FieldIndex::ForPropertyIndex(object->map(), i).offset());
      DCHECK_EQ(current_property_offset,
                object->map()->GetInObjectPropertyOffset(i));
      FieldIndex index = FieldIndex::ForInObjectOffset(current_property_offset,
                                                       FieldIndex::kTagged);
      raw_object->RawFastInobjectPropertyAtPut(index, value,
                                               SKIP_WRITE_BARRIER);
      current_property_offset += kTaggedSize;
    }
    DCHECK_EQ(current_property_offset, object->map()->GetInObjectPropertyOffset(
                                           current_property_index_));

    object_ = object;
  }

  void AddSlowProperty(DirectHandle<String> key, Handle<Object> value) {
    DCHECK(!object_.is_null());

    LookupIterator it(isolate_, object_, key, object_, LookupIterator::OWN);
    JSObject::DefineOwnPropertyIgnoreAttributes(&it, value, NONE).Check();
  }

  Handle<JSObject> object() {
    DCHECK(!object_.is_null());
    return object_;
  }

 private:
  template <typename Char, typename GetKeyFunction>
  V8_INLINE bool TryFastTransitionToPropertyKey(
      base::Vector<const Char> key_chars, GetKeyFunction&& get_key,
      Handle<String>* key_out) {
    Handle<String> expected_key;
    DirectHandle<Map> target_map;

    InternalIndex descriptor_index(current_property_index_);
    if (IsOnExpectedFinalMapFastPath()) {
      expected_key = handle(
          Cast<String>(
              expected_final_map_->instance_descriptors(isolate_)->GetKey(
                  descriptor_index)),
          isolate_);
      target_map = expected_final_map_;
    } else {
      TransitionsAccessor transitions(isolate_, *map_);
      auto expected_transition = transitions.ExpectedTransition(key_chars);
      if (!expected_transition.first.is_null()) {
        target_map = expected_transition.second;

        DCHECK_EQ(target_map->instance_descriptors()
                      ->GetDetails(descriptor_index)
                      .location(),
                  PropertyLocation::kField);
        map_ = target_map;
        return true;
      }
    }

    DirectHandle<String> key = *key_out = get_key(expected_key);
    if (key.is_identical_to(expected_key)) {
      DCHECK_EQ(target_map->instance_descriptors()
                    ->GetDetails(descriptor_index)
                    .location(),
                PropertyLocation::kField);
      map_ = target_map;
      return true;
    }

    if (IsOnExpectedFinalMapFastPath()) {
      RewindExpectedFinalMapFastPathToBeforeCurrent();
      property_count_in_expected_final_map_ = 0;
    }

    MaybeHandle<Map> maybe_target =
        TransitionsAccessor(isolate_, *map_).FindTransitionToField(key);
    if (!maybe_target.ToHandle(&target_map)) return false;

    map_ = target_map;
    return true;
  }

  V8_INLINE bool TryGeneralizeFieldToValue(DirectHandle<Object> value) {
    DCHECK_LT(current_property_index_, map_->NumberOfOwnDescriptors());

    InternalIndex descriptor_index(current_property_index_);
    PropertyDetails current_details =
        map_->instance_descriptors(isolate_)->GetDetails(descriptor_index);
    Representation expected_representation = current_details.representation();

    DCHECK_EQ(current_details.kind(), PropertyKind::kData);
    DCHECK_EQ(current_details.location(), PropertyLocation::kField);

    if (!Object::FitsRepresentation(*value, expected_representation)) {
      Representation representation =
          Object::OptimalRepresentation(*value, isolate_);
      representation = representation.generalize(expected_representation);
      if (!expected_representation.CanBeInPlaceChangedTo(representation)) {
        if (IsOnExpectedFinalMapFastPath()) {
          RewindExpectedFinalMapFastPathToIncludeCurrent();
          property_count_in_expected_final_map_ = 0;
        }
        MapUpdater mu(isolate_, map_);
        Handle<Map> new_map = mu.ReconfigureToDataField(
            descriptor_index, current_details.attributes(),
            current_details.constness(), representation,
            FieldType::Any(isolate_));

        if (new_map->is_dictionary_map()) return false;
        map_ = new_map;
        DCHECK(representation.IsDouble());
        RegisterFieldNeedsFreshHeapNumber(value);
      } else {
        DCHECK(!representation.IsDouble());
        DirectHandle<FieldType> value_type =
            Object::OptimalType(*value, isolate_, representation);
        MapUpdater::GeneralizeField(isolate_, map_, descriptor_index,
                                    current_details.constness(), representation,
                                    value_type);
      }
    } else if (expected_representation.IsHeapObject() &&
               !FieldType::NowContains(
                   map_->instance_descriptors(isolate_)->GetFieldType(
                       descriptor_index),
                   value)) {
      DirectHandle<FieldType> value_type =
          Object::OptimalType(*value, isolate_, expected_representation);
      MapUpdater::GeneralizeField(isolate_, map_, descriptor_index,
                                  current_details.constness(),
                                  expected_representation, value_type);
    } else if (expected_representation.IsDouble()) {
      RegisterFieldNeedsFreshHeapNumber(value);
    }

    DCHECK(FieldType::NowContains(
        map_->instance_descriptors(isolate_)->GetFieldType(descriptor_index),
        value));
    return true;
  }

  bool TryInitializeMapFromExpectedFinalMap() {
    if (expected_final_map_.is_null()) return false;
    if (expected_final_map_->elements_kind() != elements_kind_) return false;

    int property_count_in_expected_final_map =
        expected_final_map_->NumberOfOwnDescriptors();
    if (property_count_in_expected_final_map < expected_property_count_)
      return false;

    map_ = expected_final_map_;
    property_count_in_expected_final_map_ =
        property_count_in_expected_final_map;
    return true;
  }

  void InitializeMapFromZero() {
    DCHECK_EQ(current_property_index_, 0);

    map_ = isolate_->factory()->ObjectLiteralMapFromCache(
        isolate_->native_context(), expected_property_count_);
    if (elements_kind_ == DICTIONARY_ELEMENTS) {
      map_ = Map::AsElementsKind(isolate_, map_, elements_kind_);
    } else {
      DCHECK_EQ(map_->elements_kind(), elements_kind_);
    }
  }

  V8_INLINE bool IsOnExpectedFinalMapFastPath() const {
    DCHECK_IMPLIES(property_count_in_expected_final_map_ > 0,
                   !expected_final_map_.is_null());
    return current_property_index_ < property_count_in_expected_final_map_;
  }

  void RewindExpectedFinalMapFastPathToBeforeCurrent() {
    DCHECK_GT(property_count_in_expected_final_map_, 0);
    if (current_property_index_ == 0) {
      InitializeMapFromZero();
      DCHECK_EQ(0, map_->NumberOfOwnDescriptors());
    }
    if (current_property_index_ == 0) {
      return;
    }
    DCHECK_EQ(*map_, *expected_final_map_);
    map_ = handle(map_->FindFieldOwner(
                      isolate_, InternalIndex(current_property_index_ - 1)),
                  isolate_);
  }

  void RewindExpectedFinalMapFastPathToIncludeCurrent() {
    DCHECK_EQ(*map_, *expected_final_map_);
    map_ = handle(expected_final_map_->FindFieldOwner(
                      isolate_, InternalIndex(current_property_index_)),
                  isolate_);
  }

  V8_INLINE void RegisterFieldNeedsFreshHeapNumber(DirectHandle<Object> value) {
    if (heap_number_mode_ == kHeapNumbersGuaranteedUniquelyOwned &&
        !IsSmi(*value)) {
      DCHECK(IsHeapNumber(*value));
      return;
    }
    extra_heap_numbers_needed_++;
  }

  V8_INLINE void AdvanceToNextProperty() { current_property_index_++; }

  Isolate* isolate_;
  ElementsKind elements_kind_;
  int expected_property_count_;
  HeapNumberMode heap_number_mode_;

  DirectHandle<Map> map_;
  int current_property_index_ = 0;
  int extra_heap_numbers_needed_ = 0;

  Handle<JSObject> object_;

  DirectHandle<Map> expected_final_map_ = {};
  int property_count_in_expected_final_map_ = 0;
};

// ── RdnNamedPropertyValueIterator ──────────────────────────────────
// Iterates over already-collected RdnProperty values for
// RdnDataObjectBuilder::CreateAndInitialiseObject (the "revisit values" phase).
class RdnNamedPropertyValueIterator {
 public:
  RdnNamedPropertyValueIterator(const RdnProperty* it,
                                const RdnProperty* end V8_ALLOW_UNUSED)
      : it_(it) {
    DCHECK_LE(it, end);
  }

  RdnNamedPropertyValueIterator& operator++() {
    it_++;
    return *this;
  }

  DirectHandle<Object> operator*() { return it_->value; }

  bool operator!=(const RdnNamedPropertyValueIterator& other) const {
    return it_ != other.it_;
  }

 private:
  const RdnProperty* it_;
};

}  // namespace

// ── RdnNamedPropertyIterator ──────────────────────────────────────
// Implements the iterator protocol required by RdnDataObjectBuilder::
// BuildFromIterator. Defers string materialization: GetKeyChars() returns raw
// chars from the source buffer, GetKey() calls MakeString() only when needed.
template <typename Char>
class RdnParser<Char>::RdnNamedPropertyIterator {
 public:
  RdnNamedPropertyIterator(RdnParser<Char>& parser, const RdnProperty* it,
                            const RdnProperty* end)
      : parser_(parser), start_(it), it_(it), end_(end) {
    DCHECK_LE(it_, end_);
  }

  void Advance() {
    DCHECK_LT(it_, end_);
    it_++;
  }

  bool Done() const {
    DCHECK_LE(it_, end_);
    return it_ == end_;
  }

  base::Vector<const Char> GetKeyChars() {
    // For pre-materialized keys (default RdnString, length 0), return empty
    // vector. The builder's ExpectedTransition will miss and fall through to
    // GetKey() which returns the materialized string.
    return parser_.GetKeyChars(it_->string);
  }
  Handle<String> GetKey(Handle<String> expected_key_hint) {
    if (!it_->materialized_key.is_null()) return it_->materialized_key;
    return parser_.MakeString(it_->string, expected_key_hint);
  }
  Handle<Object> GetValue(bool will_revisit_value) {
    return it_->value;
  }
  RdnNamedPropertyValueIterator RevisitValues() {
    return RdnNamedPropertyValueIterator(start_, it_);
  }

 private:
  RdnParser<Char>& parser_;

  const RdnProperty* start_;
  const RdnProperty* it_;
  const RdnProperty* end_;
};

// ── Constructor ───────────────────────────────────────────────────
// Registers GC epilogue callback for pointer relocation.
// Reference: json-parser.cc:347-382

template <typename Char>
RdnParser<Char>::RdnParser(Isolate* isolate, Handle<String> source)
    : isolate_(isolate),
      factory_(isolate->factory()),
      source_(source),
      chars_(nullptr),
      end_(nullptr),
      cursor_(nullptr),
      has_error_(false),
      chars_may_relocate_(false) {
  source_ = String::Flatten(isolate_, source_);

  // Pre-allocate the GC-safe map cache before entering DisallowGC scope.
  object_map_cache_ = factory_->NewFixedArray(kObjectMapCacheSize);
  // Cache the Object constructor for fast empty {} creation.
  object_constructor_ = handle(isolate_->native_context()->object_function(), isolate_);

  if (StringShape(*source_).IsExternal()) {
    chars_ =
        static_cast<const Char*>(Cast<SeqExternalString>(*source_)->GetChars());
    chars_may_relocate_ = false;
  } else {
    DisallowGarbageCollection no_gc;
    isolate->main_thread_local_heap()->AddGCEpilogueCallback(
        UpdatePointersCallback, this);
    chars_ = Cast<SeqString>(*source_)->GetChars(no_gc);
    chars_may_relocate_ = true;
  }
  cursor_ = chars_;
  end_ = chars_ + source_->length();
}

// ── Destructor ────────────────────────────────────────────────────
// Removes GC epilogue callback.
// Reference: json-parser.cc:573-585

template <typename Char>
RdnParser<Char>::~RdnParser() {
  if (chars_may_relocate_) {
    Cast<SeqString>(*source_);  // Shape check.
    isolate_->main_thread_local_heap()->RemoveGCEpilogueCallback(
        UpdatePointersCallback, this);
  } else {
    Cast<SeqExternalString>(*source_);  // Shape check.
  }
}

// ── Public entry point ────────────────────────────────────────────

template <typename Char>
MaybeHandle<Object> RdnParser<Char>::Parse(Isolate* isolate,
                                           Handle<String> source) {
  HighAllocationThroughputScope high_throughput_scope(V8::GetCurrentPlatform());
  Handle<Object> result;
  {
    RdnParser parser(isolate, source);
    ASSIGN_RETURN_ON_EXCEPTION(isolate, result, parser.ParseRdn());
  }
  return result;
}

template <typename Char>
MaybeHandle<Object> RdnParser<Char>::ParseRdn() {
  MaybeHandle<Object> result = ParseValue();
  if (has_error_) return MaybeHandle<Object>();

  SkipWhitespace();
  if (!IsAtEnd()) {
    ReportError("Unexpected data after value");
    return MaybeHandle<Object>();
  }

  return result;
}

// ── Helpers ───────────────────────────────────────────────────────

template <typename Char>
void RdnParser<Char>::ReportError(const char* message) {
  if (has_error_) return;
  has_error_ = true;
  int pos = static_cast<int>(cursor_ - chars_);
  char buf[128];
  snprintf(buf, sizeof(buf), "%s at position %d", message, pos);
  Handle<String> error_str = factory_->NewStringFromAsciiChecked(buf);
  Handle<Object> error = factory_->NewSyntaxError(
      MessageTemplate::kJsonParseUnexpectedEOS, error_str);
  isolate_->Throw(*error);
}

// ── FastKeyMatch — raw byte comparison without string allocation ──
// Returns true when bytes at cursor_ match the expected key and the next
// character is a closing '"' (proving no escape sequences).
// Works for both Char=uint8_t and Char=uint16_t via CompareCharsEqual.

template <typename Char>
bool RdnParser<Char>::FastKeyMatch(const uint8_t* key_chars,
                                   uint32_t key_length) {
  return key_length < remaining_chars() &&
         *(cursor_ + key_length) == '"' &&
         CompareCharsEqual(key_chars, cursor_, key_length);
}

// ── Deferred string scanning ──────────────────────────────────────
// Scans a JSON-compatible string without allocating. Returns a descriptor
// with (start, length, has_escape, needs_conversion, internalize).
// The opening '"' must have already been consumed.
// Reference: json-parser.cc:2511-2602

template <typename Char>
base::uc32 RdnParser<Char>::ScanUnicodeCharacter() {
  base::uc32 value = 0;
  for (int i = 0; i < 4; i++) {
    Advance();
    if (IsAtEnd()) return kInvalidUnicodeCharacter;
    int digit = base::HexValue(static_cast<uint32_t>(*cursor_));
    if (V8_UNLIKELY(digit < 0)) return kInvalidUnicodeCharacter;
    value = value * 16 + digit;
  }
  return value;
}

template <typename Char>
RdnString RdnParser<Char>::ScanRdnString(bool needs_internalization) {
  DisallowGarbageCollection no_gc;
  uint32_t start = position();
  uint32_t offset = start;
  bool has_escape = false;
  base::uc32 bits = 0;

  while (true) {
    // Scan forward using MayTerminate flags — auto-vectorizable.
    cursor_ = std::find_if(cursor_, end_, [&bits](Char c) {
      if (sizeof(Char) == 2 && V8_UNLIKELY(c > unibrow::Latin1::kMaxChar)) {
        bits |= c;
        return false;
      }
      return MayTerminateRdnString(character_rdn_scan_flags[c]);
    });

    if (V8_UNLIKELY(IsAtEnd())) {
      AllowGarbageCollection allow_before_exception;
      ReportError("Unterminated string");
      return RdnString();
    }

    if (*cursor_ == '"') {
      uint32_t end = position();
      Advance();  // consume closing "
      uint32_t length = end - offset;
      bool convert = sizeof(Char) == 1 ? bits > unibrow::Latin1::kMaxChar
                                       : bits <= unibrow::Latin1::kMaxChar;
      constexpr int kMaxInternalizedStringValueLength = 10;
      bool internalize =
          needs_internalization ||
          (sizeof(Char) == 1 && length < kMaxInternalizedStringValueLength);
      return RdnString(start, length, convert, internalize, has_escape);
    }

    if (*cursor_ == '\\') {
      has_escape = true;
      base::uc32 c = static_cast<base::uc32>(*(cursor_ + 1));
      if (V8_UNLIKELY(cursor_ + 1 >= end_)) {
        AllowGarbageCollection allow_before_exception;
        ReportError("Unexpected end of input in string");
        return RdnString();
      }
      Advance();  // skip backslash

      switch (GetEscapeKind(character_rdn_scan_flags[c & 0xFF])) {
        case EscapeKind::kSelf:
        case EscapeKind::kBackspace:
        case EscapeKind::kTab:
        case EscapeKind::kNewLine:
        case EscapeKind::kFormFeed:
        case EscapeKind::kCarriageReturn:
          offset += 1;
          break;
        case EscapeKind::kUnicode: {
          base::uc32 value = ScanUnicodeCharacter();
          if (value == kInvalidUnicodeCharacter) {
            AllowGarbageCollection allow_before_exception;
            ReportError("Invalid unicode escape");
            return RdnString();
          }
          bits |= value;
          offset += 5 - (value > static_cast<base::uc32>(
                                     unibrow::Utf16::kMaxNonSurrogateCharCode));
          break;
        }
        case EscapeKind::kIllegal:
          AllowGarbageCollection allow_before_exception;
          ReportError("Invalid escape character");
          return RdnString();
      }

      Advance();  // skip escaped char
      continue;
    }

    // Control character < 0x20
    DCHECK_LT(*cursor_, 0x20);
    AllowGarbageCollection allow_before_exception;
    ReportError("Invalid control character in string");
    return RdnString();
  }
}

// ── String materialization ────────────────────────────────────────
// Creates a V8 String from an RdnString descriptor.
// Reference: json-parser.cc:2370-2434

template <typename Char>
template <typename SinkChar>
void RdnParser<Char>::DecodeString(SinkChar* sink, uint32_t start,
                                    uint32_t length) {
  const Char* cursor = chars_ + start;
  while (length > 0) {
    const Char* backslash_pos = std::find(cursor, cursor + length, '\\');
    size_t to_copy = backslash_pos - cursor;
    std::copy_n(cursor, to_copy, sink);
    length -= static_cast<uint32_t>(to_copy);
    cursor += to_copy;
    sink += to_copy;

    if (length == 0) return;

    cursor++;  // skip backslash

    switch (GetEscapeKind(character_rdn_scan_flags[*cursor])) {
      case EscapeKind::kSelf:
        *sink++ = *cursor;
        length--;
        break;
      case EscapeKind::kBackspace:
        *sink++ = '\x08';
        length--;
        break;
      case EscapeKind::kTab:
        *sink++ = '\x09';
        length--;
        break;
      case EscapeKind::kNewLine:
        *sink++ = '\x0A';
        length--;
        break;
      case EscapeKind::kFormFeed:
        *sink++ = '\x0C';
        length--;
        break;
      case EscapeKind::kCarriageReturn:
        *sink++ = '\x0D';
        length--;
        break;
      case EscapeKind::kUnicode: {
        base::uc32 value = 0;
        for (int i = 0; i < 4; i++) {
          value = value * 16 + base::HexValue(*++cursor);
        }
        if (value <=
            static_cast<base::uc32>(unibrow::Utf16::kMaxNonSurrogateCharCode)) {
          *sink++ = value;
          length--;
        } else {
          *sink++ = unibrow::Utf16::LeadSurrogate(value);
          *sink++ = unibrow::Utf16::TrailSurrogate(value);
          length -= 2;
        }
        break;
      }
      case EscapeKind::kIllegal:
        UNREACHABLE();
    }
    cursor++;
  }
}

template <typename Char>
template <typename SinkSeqString>
Handle<String> RdnParser<Char>::DecodeString(
    const RdnString& string, Handle<SinkSeqString> intermediate,
    Handle<String> hint) {
  using SinkChar = typename SinkSeqString::Char;
  {
    DisallowGarbageCollection no_gc;
    SinkChar* dest = intermediate->GetChars(no_gc);
    if (!string.has_escape()) {
      DCHECK(!string.internalize());
      CopyChars(dest, chars_ + string.start(), string.length());
      return intermediate;
    }
    DecodeString(dest, string.start(), string.length());

    if (!string.internalize()) return intermediate;

    base::Vector<const SinkChar> data(dest, string.length());
    if (!hint.is_null() && Matches(data, hint)) return hint;
  }

  DCHECK_EQ(intermediate->length(), string.length());
  return factory_->InternalizeString(intermediate);
}

template <typename Char>
Handle<String> RdnParser<Char>::MakeString(const RdnString& string,
                                            Handle<String> hint) {
  if (string.length() == 0) return factory_->empty_string();
  if (string.length() == 1) {
    uint16_t first_char;
    if (!string.has_escape()) {
      first_char = chars_[string.start()];
    } else {
      DecodeString(&first_char, string.start(), 1);
    }
    return factory_->LookupSingleCharacterStringFromCode(first_char);
  }

  if (string.internalize() && !string.has_escape()) {
    if (!hint.is_null()) {
      base::Vector<const Char> data(chars_ + string.start(), string.length());
      if (Matches(data, hint)) return hint;
    }
    if (chars_may_relocate_) {
      return factory_->InternalizeSubString(Cast<SeqString>(source_),
                                            string.start(), string.length(),
                                            string.needs_conversion());
    }
    base::Vector<const Char> chars(chars_ + string.start(), string.length());
    return factory_->InternalizeString(chars, string.needs_conversion());
  }

  if (sizeof(Char) == 1 ? V8_LIKELY(!string.needs_conversion())
                        : string.needs_conversion()) {
    Handle<SeqOneByteString> intermediate =
        factory_->NewRawOneByteString(string.length()).ToHandleChecked();
    return DecodeString(string, intermediate, hint);
  }

  Handle<SeqTwoByteString> intermediate =
      factory_->NewRawTwoByteString(string.length()).ToHandleChecked();
  return DecodeString(string, intermediate, hint);
}

// ── Value dispatch (inline hot path) ──────────────────────────────
// Handles the 7 common JSON types inline at call sites for zero function-call
// overhead. Falls through to ParseValueSlow for RDN-specific types.
// Reference: json-parser.cc ParseJsonValueRecursive (V8_INLINE).

template <typename Char>
V8_INLINE MaybeHandle<Object> RdnParser<Char>::ParseValue() {
  if (V8_UNLIKELY(has_error_)) return MaybeHandle<Object>();

  SkipWhitespace();
  if (V8_UNLIKELY(IsAtEnd())) {
    ReportError("Unexpected end of input");
    return MaybeHandle<Object>();
  }

  base::uc32 c = CurrentChar();
  if (c == '"') return ParseString();
  if (c == '{') return ParseBrace();
  if (c == '[') return ParseArray();
  if (V8_LIKELY(IsDecimalDigit(c) || c == '-')) {
    // -Infinity starts with '-' followed by 'I'. Route to slow path so
    // ParseNumber's hot path doesn't need to check for it.
    if (V8_UNLIKELY(c == '-' && remaining_chars() > 1 && Peek(1) == 'I'))
      return ParseValueSlow();
    return ParseNumber();
  }
  if (c == 't') {
    if (V8_LIKELY(Match("true", 4))) {
      Advance(4);
      return factory_->true_value();
    }
  }
  if (c == 'f') {
    if (V8_LIKELY(Match("false", 5))) {
      Advance(5);
      return factory_->false_value();
    }
  }
  if (c == 'n') {
    if (V8_LIKELY(Match("null", 4))) {
      Advance(4);
      return factory_->null_value();
    }
  }
  return ParseValueSlow();
}

// ── Value dispatch (cold path for RDN-specific types) ──────────────
template <typename Char>
MaybeHandle<Object> RdnParser<Char>::ParseValueSlow() {
  base::uc32 c = CurrentChar();
  RdnToken token = (c <= unibrow::Latin1::kMaxChar)
                       ? one_char_rdn_tokens[c]
                       : RdnToken::ILLEGAL;

  switch (token) {
    case RdnToken::LPAREN:
      return ParseTuple();

    case RdnToken::NAN_LITERAL:
      if (!Match("NaN", 3)) {
        ReportError("Expected 'NaN'");
        return MaybeHandle<Object>();
      }
      Advance(3);
      return factory_->NewNumber(std::numeric_limits<double>::quiet_NaN());

    case RdnToken::INFINITY_LITERAL:
      if (!Match("Infinity", 8)) {
        ReportError("Expected 'Infinity'");
        return MaybeHandle<Object>();
      }
      Advance(8);
      return factory_->NewNumber(std::numeric_limits<double>::infinity());

    case RdnToken::DATETIME:
      return ParseDateTime();

    case RdnToken::REGEX:
      return ParseRegex();

    case RdnToken::MAP_KEYWORD:
      return ParseMapKeyword();

    case RdnToken::SET_KEYWORD:
      return ParseSetKeyword();

    case RdnToken::BINARY_B64:
      return ParseBinaryB64();

    case RdnToken::BINARY_HEX:
      return ParseBinaryHex();

    case RdnToken::NUMBER:
      // Reached via ParseValue for -Infinity (c == '-', Peek(1) == 'I').
      return ParseNumber();

    default:
      ReportError("Unexpected character");
      return MaybeHandle<Object>();
  }
}

// ── ParseValue with feedback ───────────────────────────────────────
// Stores feedback in array_element_feedback_ so that ParseBrace can attempt
// the fast-key path, then delegates to ParseValue() and clears feedback.

template <typename Char>
MaybeHandle<Object> RdnParser<Char>::ParseValue(Handle<Map> feedback) {
  array_element_feedback_ = feedback;
  MaybeHandle<Object> result = ParseValue();
  array_element_feedback_ = Handle<Map>();
  return result;
}

// ── String parsing (uses deferred scan) ───────────────────────────

template <typename Char>
MaybeHandle<Object> RdnParser<Char>::ParseString() {
  Advance();  // skip opening "
  RdnString desc = ScanRdnString(false);
  if (has_error_) return MaybeHandle<Object>();
  return MakeString(desc);
}

// ── Number parsing (Smi-first) ────────────────────────────────────
// Accumulates up to 9 digits as int32 directly. Only falls through to
// StringToDouble for decimals/exponents. Handles BigInt 'n' suffix.
// Reference: json-parser.cc:2258-2345

template <typename Char>
MaybeHandle<Object> RdnParser<Char>::ParseNumber() {
  // Handle -Infinity
  if (CurrentChar() == '-' && Match("-Infinity", 9)) {
    Advance(9);
    return factory_->NewNumber(-std::numeric_limits<double>::infinity());
  }

  const Char* start = cursor_;
  int sign = 1;

  {
    DisallowGarbageCollection no_gc;

    base::uc32 c = *cursor_;
    if (c == '-') {
      sign = -1;
      cursor_++;
      if (cursor_ >= end_) {
        AllowGarbageCollection allow_gc;
        ReportError("Unexpected end of input");
        return MaybeHandle<Object>();
      }
      c = *cursor_;
    }

    if (c == '0') {
      cursor_++;
      c = (cursor_ < end_) ? *cursor_ : kEndOfString;

      // BigInt: 0n
      if (c == 'n') {
        cursor_++;
        AllowGarbageCollection allow_gc;
        return BigInt::FromInt64(isolate_, 0);
      }

      // Check for leading-zero error
      if (c != kEndOfString && IsDecimalDigit(c)) {
        AllowGarbageCollection allow_gc;
        ReportError("Leading zeros are not allowed");
        return MaybeHandle<Object>();
      }

      // 0 followed by non-number-part → Smi 0
      if (c == kEndOfString ||
          !base::IsInRange(c, static_cast<base::uc32>(0),
                           static_cast<base::uc32>(unibrow::Latin1::kMaxChar)) ||
          !IsNumberPart(character_rdn_scan_flags[c])) {
        if (sign > 0) {
          AllowGarbageCollection allow_gc;
          return handle(Smi::FromInt(0), isolate_);
        }
        // -0 → HeapNumber
      }
    } else if (IsDecimalDigit(c)) {
      // Smi-first: accumulate up to 9 digits as int32.
      // 9 digits guarantees the result fits in a Smi.
      const Char* smi_start = cursor_;
      static_assert(Smi::IsValid(-999999999));
      static_assert(Smi::IsValid(999999999));
      const int kMaxSmiLength = 9;
      int32_t i = 0;
      const Char* stop = cursor_ + kMaxSmiLength;
      if (stop > end_) stop = end_;
      while (cursor_ < stop && IsDecimalDigit(*cursor_)) {
        i = (i * 10) + ((*cursor_) - '0');
        cursor_++;
      }

      if (V8_UNLIKELY(smi_start == cursor_)) {
        AllowGarbageCollection allow_gc;
        ReportError("Invalid number");
        return MaybeHandle<Object>();
      }

      c = (cursor_ < end_) ? *cursor_ : kEndOfString;

      // BigInt suffix 'n' after integer digits
      if (c == 'n') {
        cursor_++;
        AllowGarbageCollection allow_gc;
        // Skip remaining digits that didn't fit in 9-digit window
        // For small BigInts (≤9 digits), use direct conversion
        if (cursor_ - 1 - smi_start <= kMaxSmiLength) {
          int64_t value = static_cast<int64_t>(i) * sign;
          return BigInt::FromInt64(isolate_, value);
        }
        // Large BigInt — fall through to string conversion below
        cursor_ = start;
        goto bigint_slow_path;
      }

      // No decimal/exponent/more digits → Smi fast path
      if (c == kEndOfString ||
          !base::IsInRange(c, static_cast<base::uc32>(0),
                           static_cast<base::uc32>(unibrow::Latin1::kMaxChar)) ||
          !IsNumberPart(character_rdn_scan_flags[c])) {
        AllowGarbageCollection allow_gc;
        return handle(Smi::FromInt(i * sign), isolate_);
      }

      // More digits beyond 9 — advance past them
      cursor_ = std::find_if(cursor_, end_, [](Char ch) {
        return !IsDecimalDigit(ch);
      });
      c = (cursor_ < end_) ? *cursor_ : kEndOfString;

      // BigInt suffix after long integer
      if (c == 'n') {
        cursor_++;
        AllowGarbageCollection allow_gc;
        goto bigint_slow_path_from_current;
      }
    } else {
      AllowGarbageCollection allow_gc;
      ReportError("Invalid number");
      return MaybeHandle<Object>();
    }

    // Fractional part
    c = (cursor_ < end_) ? *cursor_ : kEndOfString;
    if (c == '.') {
      cursor_++;
      if (cursor_ >= end_ || !IsDecimalDigit(*cursor_)) {
        AllowGarbageCollection allow_gc;
        ReportError("Expected digit after decimal point");
        return MaybeHandle<Object>();
      }
      cursor_ = std::find_if(cursor_, end_, [](Char ch) {
        return !IsDecimalDigit(ch);
      });
    }

    // Exponent part
    c = (cursor_ < end_) ? *cursor_ : kEndOfString;
    if (c == 'e' || c == 'E') {
      cursor_++;
      c = (cursor_ < end_) ? *cursor_ : kEndOfString;
      if (c == '+' || c == '-') {
        cursor_++;
        c = (cursor_ < end_) ? *cursor_ : kEndOfString;
      }
      if (!IsDecimalDigit(c)) {
        AllowGarbageCollection allow_gc;
        ReportError("Expected digit in exponent");
        return MaybeHandle<Object>();
      }
      cursor_ = std::find_if(cursor_, end_, [](Char ch) {
        return !IsDecimalDigit(ch);
      });
    }

    // Reject trailing 'n' — BigInt cannot have decimal point or exponent
    if (cursor_ < end_ && *cursor_ == 'n') {
      AllowGarbageCollection allow_gc;
      ReportError("BigInt cannot have decimal point or exponent");
      return MaybeHandle<Object>();
    }

    // Convert to double using V8's StringToDouble (not strtod).
    base::Vector<const Char> chars(start, cursor_ - start);
    double value = StringToDouble(chars, NO_CONVERSION_FLAG,
                                  std::numeric_limits<double>::quiet_NaN());
    DCHECK(!std::isnan(value));

    // Check if the double is actually a Smi
    int smi_value;
    if (DoubleToSmiInteger(value, &smi_value)) {
      AllowGarbageCollection allow_gc;
      return handle(Smi::FromInt(smi_value), isolate_);
    }

    AllowGarbageCollection allow_gc;
    return factory_->NewHeapNumber(value);
  }

  // BigInt slow paths (need string conversion)
bigint_slow_path : {
    // cursor_ was reset to start. Scan the integer part.
    if (*cursor_ == '-') cursor_++;
    while (cursor_ < end_ && IsDecimalDigit(*cursor_)) cursor_++;
    if (cursor_ < end_ && *cursor_ == 'n') cursor_++;
  }
bigint_slow_path_from_current : {
    int len = static_cast<int>((cursor_ - start));
    // Exclude trailing 'n'
    if (len > 0 && start[len - 1] == 'n') len--;
    Handle<String> num_str;
    if (sizeof(Char) == 1) {
      num_str = factory_->NewStringFromOneByte(
          base::Vector<const uint8_t>(
              reinterpret_cast<const uint8_t*>(start), len)).ToHandleChecked();
    } else {
      num_str = factory_->NewStringFromTwoByte(
          base::Vector<const base::uc16>(
              reinterpret_cast<const base::uc16*>(start), len)).ToHandleChecked();
    }
    MaybeHandle<BigInt> result = StringToBigInt(isolate_, num_str);
    if (result.is_null()) {
      ReportError("Invalid BigInt");
      return MaybeHandle<Object>();
    }
    return result;
  }
}

// ── Raw number parsing for array fast path ────────────────────────
// Returns true if the number is a double, false if Smi.
// Sets *is_fallback if the number is not a simple numeric (BigInt, -Infinity).
// On fallback, cursor is restored to before the number.
// Reference: json-parser.cc:2258-2357 (ParseJsonNumberAsDoubleOrSmi)

template <typename Char>
bool RdnParser<Char>::ParseNumberRaw(double* result_double, int* result_smi,
                                      bool* is_fallback) {
  *is_fallback = false;
  DisallowGarbageCollection no_gc;
  const Char* start = cursor_;

  int sign = 1;
  base::uc32 c = *cursor_;
  if (c == '-') {
    sign = -1;
    cursor_++;
    if (V8_UNLIKELY(cursor_ >= end_)) {
      cursor_ = start;
      *is_fallback = true;
      return false;
    }
    c = *cursor_;
  }

  if (c == '0') {
    cursor_++;
    c = (cursor_ < end_) ? *cursor_ : kEndOfString;

    // BigInt: 0n → fallback
    if (c == 'n') {
      cursor_ = start;
      *is_fallback = true;
      return false;
    }

    // Leading zero followed by digit → error, let ParseNumber handle it
    if (c != kEndOfString && IsDecimalDigit(c)) {
      cursor_ = start;
      *is_fallback = true;
      return false;
    }

    // 0 not followed by number part → Smi 0 (or -0.0 for negative)
    if (c == kEndOfString ||
        !base::IsInRange(c, static_cast<base::uc32>(0),
                         static_cast<base::uc32>(unibrow::Latin1::kMaxChar)) ||
        !IsNumberPart(character_rdn_scan_flags[c])) {
      if (sign > 0) {
        *result_smi = 0;
        return false;  // Smi 0
      }
      // -0 → double
      *result_double = -0.0;
      return true;
    }
    // 0 followed by '.', 'e', 'E' → fall through to decimal handling
  } else if (IsDecimalDigit(c)) {
    // Smi-first: accumulate up to 9 digits as int32.
    static_assert(Smi::IsValid(-999999999));
    static_assert(Smi::IsValid(999999999));
    const int kMaxSmiLength = 9;
    int32_t i = 0;
    const Char* stop = cursor_ + kMaxSmiLength;
    if (stop > end_) stop = end_;
    while (cursor_ < stop && IsDecimalDigit(*cursor_)) {
      i = (i * 10) + ((*cursor_) - '0');
      cursor_++;
    }

    c = (cursor_ < end_) ? *cursor_ : kEndOfString;

    // BigInt suffix 'n' → fallback
    if (c == 'n') {
      cursor_ = start;
      *is_fallback = true;
      return false;
    }

    // No decimal/exponent/more digits → Smi
    if (c == kEndOfString ||
        !base::IsInRange(c, static_cast<base::uc32>(0),
                         static_cast<base::uc32>(unibrow::Latin1::kMaxChar)) ||
        !IsNumberPart(character_rdn_scan_flags[c])) {
      *result_smi = i * sign;
      return false;  // Smi
    }

    // More digits beyond 9
    cursor_ = std::find_if(cursor_, end_, [](Char ch) {
      return !IsDecimalDigit(ch);
    });
    c = (cursor_ < end_) ? *cursor_ : kEndOfString;

    // BigInt suffix after long integer → fallback
    if (c == 'n') {
      cursor_ = start;
      *is_fallback = true;
      return false;
    }
  } else {
    // Not a digit after optional '-'
    cursor_ = start;
    *is_fallback = true;
    return false;
  }

  // Fractional part
  c = (cursor_ < end_) ? *cursor_ : kEndOfString;
  if (c == '.') {
    cursor_++;
    if (cursor_ >= end_ || !IsDecimalDigit(*cursor_)) {
      cursor_ = start;
      *is_fallback = true;
      return false;
    }
    cursor_ = std::find_if(cursor_, end_, [](Char ch) {
      return !IsDecimalDigit(ch);
    });
  }

  // Exponent part
  c = (cursor_ < end_) ? *cursor_ : kEndOfString;
  if (c == 'e' || c == 'E') {
    cursor_++;
    c = (cursor_ < end_) ? *cursor_ : kEndOfString;
    if (c == '+' || c == '-') {
      cursor_++;
      c = (cursor_ < end_) ? *cursor_ : kEndOfString;
    }
    if (!IsDecimalDigit(c)) {
      cursor_ = start;
      *is_fallback = true;
      return false;
    }
    cursor_ = std::find_if(cursor_, end_, [](Char ch) {
      return !IsDecimalDigit(ch);
    });
  }

  // Reject trailing 'n' (BigInt can't have decimal/exponent)
  if (cursor_ < end_ && *cursor_ == 'n') {
    cursor_ = start;
    *is_fallback = true;
    return false;
  }

  // Convert to double using V8's StringToDouble.
  base::Vector<const Char> chars(start, cursor_ - start);
  double value = StringToDouble(chars, NO_CONVERSION_FLAG,
                                std::numeric_limits<double>::quiet_NaN());
  DCHECK(!std::isnan(value));

  // Check if the double is actually a Smi
  if (DoubleToSmiInteger(value, result_smi)) {
    return false;  // Smi
  }

  *result_double = value;
  return true;  // Double
}

// ── Array parsing ─────────────────────────────────────────────────
// Collects elements, then selects optimal ElementsKind.
// Number-only fast path accumulates raw C++ values without Handle allocation.
// Reference: json-parser.cc:1420-1450 (BuildJsonArray),
//            json-parser.cc:1808-1869 (ParseJsonArray)

template <typename Char>
MaybeHandle<Object> RdnParser<Char>::ParseArray() {
  HandleScope handle_scope(isolate_);
  Advance();  // skip [
  SkipWhitespace();

  if (!IsAtEnd() && CurrentChar() == ']') {
    Advance();
    return handle_scope.CloseAndEscape(
        factory_->NewJSArray(0, PACKED_SMI_ELEMENTS));
  }

  size_t elem_start = element_stack_.size();
  bool need_parse_current = false;

  // ── Number-only fast path ──────────────────────────────────────
  // Accumulate leading numbers as raw C++ int/double values without Handle
  // allocation or HeapNumber boxing. If the entire array is numbers, build
  // optimal FixedArray (PACKED_SMI) or FixedDoubleArray (PACKED_DOUBLE)
  // directly. Reference: json-parser.cc:1808-1869
  {
    base::uc32 c = CurrentChar();
    // Only enter fast path for simple numbers (digits or - followed by digit).
    // Exclude -Infinity which starts with '-' followed by 'I'.
    if (IsDecimalDigit(c) ||
        (c == '-' && remaining_chars() > 1 && IsDecimalDigit(Peek(1)))) {
      smi_elements_.clear();
      double_elements_.clear();
      bool saw_double = false;

      do {
        double dval;
        int ival;
        bool is_fallback;
        bool is_double = ParseNumberRaw(&dval, &ival, &is_fallback);
        if (is_fallback) {
          need_parse_current = true;
          break;
        }
        if (has_error_) return MaybeHandle<Object>();

        if (is_double) {
          if (!saw_double) {
            saw_double = true;
            for (int s : smi_elements_) {
              double_elements_.push_back(static_cast<double>(s));
            }
            smi_elements_.clear();
          }
          double_elements_.push_back(dval);
        } else {
          if (saw_double) {
            double_elements_.push_back(static_cast<double>(ival));
          } else {
            smi_elements_.push_back(ival);
          }
        }

        SkipWhitespace();
        if (V8_UNLIKELY(IsAtEnd())) {
          ReportError("Unexpected end of input");
          return MaybeHandle<Object>();
        }
        c = CurrentChar();

        if (c == ']') {
          // Pure number array — build directly without Handle allocation.
          Advance();
          int total = saw_double ? static_cast<int>(double_elements_.size())
                                 : static_cast<int>(smi_elements_.size());
          if (!saw_double) {
            Handle<FixedArrayBase> fixed = factory_->NewFixedArray(total);
            {
              DisallowGarbageCollection no_gc;
              Tagged<FixedArray> arr = Cast<FixedArray>(*fixed);
              for (int i = 0; i < total; i++) {
                arr->set(i, Smi::FromInt(smi_elements_[i]));
              }
            }
            return handle_scope.CloseAndEscape(
                factory_->NewJSArrayWithElements(fixed, PACKED_SMI_ELEMENTS,
                                                 total));
          } else {
            Handle<FixedArrayBase> fixed = FixedDoubleArray::New(
                isolate_, total,
                [this](int i) { return double_elements_[i]; });
            return handle_scope.CloseAndEscape(
                factory_->NewJSArrayWithElements(fixed, PACKED_DOUBLE_ELEMENTS,
                                                 total));
          }
        }

        if (V8_UNLIKELY(c != ',')) {
          ReportError("Expected ',' or ']'");
          return MaybeHandle<Object>();
        }
        Advance();  // skip ','
        SkipWhitespace();
        if (V8_UNLIKELY(IsAtEnd())) {
          ReportError("Unexpected end of input");
          return MaybeHandle<Object>();
        }
        c = CurrentChar();
      } while (IsDecimalDigit(c) ||
               (c == '-' && remaining_chars() > 1 && IsDecimalDigit(Peek(1))));

      // Fell through: non-number element encountered after some numbers.
      // Materialize accumulated numbers into element_stack_.
      if (!need_parse_current) need_parse_current = true;
      if (saw_double) {
        for (double d : double_elements_) {
          int smi_val;
          if (DoubleToSmiInteger(d, &smi_val)) {
            element_stack_.push_back(handle(Smi::FromInt(smi_val), isolate_));
          } else {
            element_stack_.push_back(factory_->NewHeapNumber(d));
          }
        }
      } else {
        for (int s : smi_elements_) {
          element_stack_.push_back(handle(Smi::FromInt(s), isolate_));
        }
      }
    }
  }

  // ── General path ───────────────────────────────────────────────
  // Parse first/current element (if not already consumed by number fast path).
  if (element_stack_.size() == elem_start || need_parse_current) {
    Handle<Object> val;
    ASSIGN_RETURN_ON_EXCEPTION(isolate_, val, ParseValue());
    element_stack_.push_back(val);
    SkipWhitespace();
  }

  while (true) {
    if (V8_UNLIKELY(IsAtEnd())) {
      ReportError("Unexpected end of input");
      element_stack_.resize(elem_start);
      return MaybeHandle<Object>();
    }
    Char c = static_cast<Char>(CurrentChar());
    if (c == ']') {
      Advance();
      break;
    }
    if (V8_UNLIKELY(c != ',')) {
      ReportError("Expected ',' or ']'");
      element_stack_.resize(elem_start);
      return MaybeHandle<Object>();
    }
    Advance();

    // Thread feedback from previous element: if the previous element was a
    // JSObject with a non-detached map, pass it as feedback to guide
    // FastKeyMatch in the next ParseBrace.
    Handle<Object> prev = element_stack_.back();
    Handle<Object> val;
    if (IsJSObject(*prev)) {
      Tagged<Map> maybe_feedback = Cast<JSObject>(*prev)->map();
      if (!maybe_feedback->IsDetached(isolate_)) {
        Handle<Map> feedback(maybe_feedback, isolate_);
        ASSIGN_RETURN_ON_EXCEPTION(isolate_, val, ParseValue(feedback));
      } else {
        ASSIGN_RETURN_ON_EXCEPTION(isolate_, val, ParseValue());
      }
    } else {
      ASSIGN_RETURN_ON_EXCEPTION(isolate_, val, ParseValue());
    }
    element_stack_.push_back(val);

    SkipWhitespace();
  }

  int len = static_cast<int>(element_stack_.size() - elem_start);

  // Select optimal ElementsKind by scanning collected elements.
  ElementsKind kind = PACKED_SMI_ELEMENTS;
  for (size_t i = elem_start; i < element_stack_.size(); i++) {
    Tagged<Object> value = *element_stack_[i];
    if (IsHeapObject(value)) {
      if (IsHeapNumber(Cast<HeapObject>(value))) {
        kind = PACKED_DOUBLE_ELEMENTS;
      } else {
        kind = PACKED_ELEMENTS;
        break;
      }
    }
  }

  Handle<FixedArrayBase> fixed;
  if (kind == PACKED_DOUBLE_ELEMENTS) {
    fixed = FixedDoubleArray::New(
        isolate_, len,
        [this, elem_start](int i) {
          return Object::NumberValue(*element_stack_[elem_start + i]);
        });
  } else {
    fixed = FixedArray::New(isolate_, len,
        [this, elem_start](int i) {
          return *element_stack_[elem_start + i];
        });
  }

  element_stack_.resize(elem_start);
  return handle_scope.CloseAndEscape(
      factory_->NewJSArrayWithElements(fixed, kind, len));
}

// ── Tuple parsing (parentheses → array) ───────────────────────────

template <typename Char>
MaybeHandle<Object> RdnParser<Char>::ParseTuple() {
  HandleScope handle_scope(isolate_);
  Advance();  // skip (
  SkipWhitespace();

  if (!IsAtEnd() && CurrentChar() == ')') {
    Advance();
    return handle_scope.CloseAndEscape(
        factory_->NewJSArray(0, PACKED_SMI_ELEMENTS));
  }

  base::SmallVector<Handle<Object>, 16> elements;

  while (true) {
    Handle<Object> val;
    ASSIGN_RETURN_ON_EXCEPTION(isolate_, val, ParseValue());
    elements.push_back(val);

    SkipWhitespace();
    if (IsAtEnd()) {
      ReportError("Unexpected end of input");
      return MaybeHandle<Object>();
    }
    Char c = static_cast<Char>(CurrentChar());
    if (c == ')') {
      Advance();
      break;
    }
    if (c != ',') {
      ReportError("Expected ',' or ')'");
      return MaybeHandle<Object>();
    }
    Advance();
  }

  int len = static_cast<int>(elements.size());
  Handle<FixedArray> fixed = factory_->NewFixedArray(len);
  for (int i = 0; i < len; i++) {
    fixed->set(i, *elements[i]);
  }
  return handle_scope.CloseAndEscape(
      factory_->NewJSArrayWithElements(fixed, PACKED_ELEMENTS, len));
}

// ── Brace disambiguation: object / Map / Set ──────────────────────

template <typename Char>
MaybeHandle<Object> RdnParser<Char>::ParseBrace() {
  Advance();  // skip {
  SkipWhitespace();

  // Empty {} → object (uses cached constructor to avoid re-lookup).
  if (!IsAtEnd() && CurrentChar() == '}') {
    Advance();
    return factory_->NewJSObject(object_constructor_);
  }

  // ── FastKeyMatch fast path ──────────────────────────────────────
  // When feedback is available from a previous array element, try to match
  // the first key directly against the descriptor array without materializing
  // any strings.
  Handle<Map> feedback = array_element_feedback_;
  array_element_feedback_ = Handle<Map>();  // consume

  if (!feedback.is_null() && !IsAtEnd() && CurrentChar() == '"') {
    using FastIterableState = DescriptorArray::FastIterableState;
    Handle<DescriptorArray> descriptors(
        feedback->instance_descriptors(), isolate_);
    int nof = feedback->NumberOfOwnDescriptors();

    if (nof > 0) {
      FastIterableState state = descriptors->fast_iterable();
      if (state == FastIterableState::kJsonFast) {
        // Try FastKeyMatch for the first key at cursor_+1 (past opening '"').
        const Char* saved_cursor = cursor_;
        bool first_key_matched = false;
        {
          DisallowGarbageCollection no_gc;
          Tagged<String> expected_key =
              Cast<String>(descriptors->GetKey(InternalIndex(0)));
          Tagged<Map> key_map = expected_key->map();
          if (InstanceTypeChecker::IsOneByteString(key_map)) {
            const uint8_t* expected_chars =
                GetFastKeyChars(isolate_, expected_key, key_map, no_gc);
            uint32_t key_length = expected_key->length();
            // cursor_ points at '"', check bytes starting at cursor_+1.
            cursor_++;  // past opening "
            first_key_matched = FastKeyMatch(expected_chars, key_length);
            if (first_key_matched) {
              cursor_ += key_length + 1;  // past key bytes + closing "
            } else {
              cursor_ = saved_cursor;  // restore
            }
          }
        }
        if (first_key_matched) {
          SkipWhitespace();
          if (!IsAtEnd() && CurrentChar() == ':') {
            // Confirmed this is an object with a matching first key.
            // Delegate to FinishObjectFastKeys (cursor is at ':').
            return FinishObjectFastKeys(feedback, descriptors, nof);
          }
          // Not ':' — could be '=>' (Map) or ',' (Set). Restore cursor.
          cursor_ = saved_cursor;
        }
      }
      // For kUnknown, we fall through to normal parsing but will pass feedback
      // to FinishObject for learning.
      // For kJsonSlow, we skip feedback entirely.
      if (state == FastIterableState::kJsonSlow) {
        feedback = Handle<Map>();  // discard
      }
    } else {
      feedback = Handle<Map>();  // no descriptors, discard
    }
  }

  // ── Map cache FastKeyMatch probe ─────────────────────────────────
  // When no array_element_feedback_ was available, try the multi-entry map
  // cache. If any cached map's first descriptor key matches the source bytes,
  // delegate to FinishObjectFastKeys — avoiding ScanRdnString + MakeString
  // for all keys. Skip entirely when cache is empty.
  if (map_cache_populated_ && !IsAtEnd() && CurrentChar() == '"') {
    const Char* saved_cursor = cursor_;
    int matched_ci = -1;
    int matched_nof = 0;
    {
      DisallowGarbageCollection no_gc;
      for (int ci = 0; ci < kObjectMapCacheSize; ci++) {
        Tagged<Object> entry = object_map_cache_->get(ci);
        if (!IsMap(entry)) continue;
        Tagged<Map> cached_map = Cast<Map>(entry);
        int nof = cached_map->NumberOfOwnDescriptors();
        if (nof == 0) continue;
        Tagged<DescriptorArray> desc = cached_map->instance_descriptors();
        Tagged<String> expected_key =
            Cast<String>(desc->GetKey(InternalIndex(0)));
        Tagged<Map> key_map = expected_key->map();
        if (!InstanceTypeChecker::IsOneByteString(key_map)) continue;
        const uint8_t* expected_chars =
            GetFastKeyChars(isolate_, expected_key, key_map, no_gc);
        uint32_t key_length = expected_key->length();
        cursor_ = saved_cursor + 1;  // past opening '"'
        if (FastKeyMatch(expected_chars, key_length)) {
          cursor_ += key_length + 1;  // past key bytes + closing '"'
          matched_ci = ci;
          matched_nof = nof;
          break;
        }
      }
      if (matched_ci < 0) cursor_ = saved_cursor;
    }
    if (matched_ci >= 0) {
      SkipWhitespace();
      if (!IsAtEnd() && CurrentChar() == ':') {
        Handle<Map> cache_feedback(
            Cast<Map>(object_map_cache_->get(matched_ci)), isolate_);
        Handle<DescriptorArray> cache_desc(
            cache_feedback->instance_descriptors(), isolate_);
        return FinishObjectFastKeys(cache_feedback, cache_desc, matched_nof);
      }
      cursor_ = saved_cursor;
    }
  }

  // Fast path: first token is a string → likely object key.
  // Parse it as a string directly and disambiguate on the separator.
  // This avoids the generic ParseValue() overhead for the common case.
  if (!IsAtEnd() && CurrentChar() == '"') {
    Advance();  // skip opening "
    RdnString key_desc = ScanRdnString(true);
    if (has_error_) return MaybeHandle<Object>();

    SkipWhitespace();
    if (IsAtEnd()) {
      ReportError("Unexpected end of input");
      return MaybeHandle<Object>();
    }
    base::uc32 sep = CurrentChar();

    if (sep == ':') {
      // Object: {"key": value, ...}
      // Pass raw RdnString descriptor — materialization deferred to builder.
      return FinishObject(key_desc, feedback);
    }
    // Materialize for non-object paths (Map, Set).
    Handle<String> first_str = MakeString(key_desc);
    if (sep == '=' && Peek(1) == '>') {
      // Map: {"key" => value, ...}
      return FinishMap(first_str);
    }
    if (sep == ',') {
      // Set: {"a", "b", ...}
      return FinishSet(first_str);
    }
    if (sep == '}') {
      // Single-element Set: {"a"}
      Advance();
      DirectHandle<JSSet> set = factory_->NewJSSet();
      Handle<OrderedHashSet> table(Cast<OrderedHashSet>(set->table()), isolate_);
      table = OrderedHashSet::Add(isolate_, table, first_str).ToHandleChecked();
      set->set_table(*table);
      return handle(*set, isolate_);
    }

    ReportError("Expected ':', '=>', ',' or '}' after value in brace");
    return MaybeHandle<Object>();
  }

  // Slow path: non-string first value (e.g. Map with number keys, Set with
  // non-string values). Fall through to generic ParseValue().
  Handle<Object> first_value;
  ASSIGN_RETURN_ON_EXCEPTION(isolate_, first_value, ParseValue());
  SkipWhitespace();

  if (IsAtEnd()) {
    ReportError("Unexpected end of input");
    return MaybeHandle<Object>();
  }
  base::uc32 next = CurrentChar();

  // : → object (first value must be string key)
  if (next == ':') {
    if (!IsString(*first_value)) {
      ReportError("Object keys must be strings");
      return MaybeHandle<Object>();
    }
    Handle<String> first_key =
        factory_->InternalizeString(Cast<String>(first_value));
    return FinishObjectMaterialized(first_key);
  }

  // => → Map
  if (next == '=' && Peek(1) == '>') {
    return FinishMap(first_value);
  }

  // , → Set (more elements)
  if (next == ',') {
    return FinishSet(first_value);
  }

  // } → single-element Set
  if (next == '}') {
    Advance();
    DirectHandle<JSSet> set = factory_->NewJSSet();
    Handle<OrderedHashSet> table(Cast<OrderedHashSet>(set->table()), isolate_);
    table = OrderedHashSet::Add(isolate_, table, first_value).ToHandleChecked();
    set->set_table(*table);
    return handle(*set, isolate_);
  }

  ReportError("Expected ':', '=>', ',' or '}' after value in brace");
  return MaybeHandle<Object>();
}

// ── FinishObjectFastKeys — zero-allocation key matching fast path ──
// Called when feedback DescriptorArray is kJsonFast and the first key has
// already been matched. cursor_ is at ':' after the first key.
// Matches remaining keys via FastKeyMatch, builds object with FastPropertyAtPut
// at known offsets. Falls back to slow path on any key mismatch.

template <typename Char>
MaybeHandle<Object> RdnParser<Char>::FinishObjectFastKeys(
    Handle<Map> feedback, Handle<DescriptorArray> descriptors,
    int nof_descriptors) {
  HandleScope handle_scope(isolate_);

  // Check for deprecated map.
  if (feedback->is_deprecated()) {
    // Fall back: re-parse as normal object. Can't easily restart since we've
    // already advanced past the first key. Materialize key from descriptor[0].
    // Actually, since this is rare, just delegate to the slow fallback below
    // with matched=0.
    // Reset: we need to go back. But we can't — cursor is past the first key.
    // Instead, materialize what we've matched and fall through.
    goto slow_fallback_start;
  }

  {
    Advance();  // skip ':'
    base::SmallVector<Handle<Object>, 16> values;

    // Parse first value.
    {
      Handle<Object> first_val;
      ASSIGN_RETURN_ON_EXCEPTION(isolate_, first_val, ParseValue());
      values.push_back(first_val);
    }
    SkipWhitespace();

    int matched = 1;

    // Try to match remaining keys.
    while (matched < nof_descriptors) {
      if (IsAtEnd() || CurrentChar() != ',') break;
      Advance();  // skip ','
      SkipWhitespace();
      if (IsAtEnd() || CurrentChar() != '"') break;

      // Try FastKeyMatch for next expected key.
      bool key_matched = false;
      {
        DisallowGarbageCollection no_gc;
        Tagged<String> expected_key =
            Cast<String>(descriptors->GetKey(InternalIndex(matched)));
        Tagged<Map> key_map = expected_key->map();
        if (InstanceTypeChecker::IsOneByteString(key_map)) {
          const uint8_t* expected_chars =
              GetFastKeyChars(isolate_, expected_key, key_map, no_gc);
          uint32_t key_length = expected_key->length();
          cursor_++;  // past opening '"'
          key_matched = FastKeyMatch(expected_chars, key_length);
          if (key_matched) {
            cursor_ += key_length + 1;  // past key bytes + closing '"'
          } else {
            cursor_--;  // restore to '"'
          }
        }
      }
      if (!key_matched) break;

      SkipWhitespace();
      if (IsAtEnd() || CurrentChar() != ':') {
        // This shouldn't happen for a well-formed object, but handle gracefully.
        break;
      }
      Advance();  // skip ':'

      Handle<Object> val;
      ASSIGN_RETURN_ON_EXCEPTION(isolate_, val, ParseValue());
      values.push_back(val);
      SkipWhitespace();
      matched++;
    }

    // Check for exact match: all keys matched and we're at '}'.
    if (matched == nof_descriptors && !IsAtEnd() && CurrentChar() == '}') {
      // Verify all fields are compatible for direct stamping.
      // FastPropertyAtPut handles all representations natively:
      //   Tagged: any value
      //   Smi: value must be a Smi
      //   Double: value must be a Number (Smi or HeapNumber)
      //   HeapObject: value must be a HeapObject (not Smi)
      bool all_compatible = true;
      {
        DisallowGarbageCollection no_gc;
        Tagged<DescriptorArray> desc = *descriptors;
        for (int i = 0; i < nof_descriptors; i++) {
          PropertyDetails details = desc->GetDetails(InternalIndex(i));
          if (details.location() != PropertyLocation::kField) {
            all_compatible = false;
            break;
          }
          Representation rep = details.representation();
          Tagged<Object> val = *values[i];
          if (rep.IsSmi()) {
            if (!IsSmi(val)) { all_compatible = false; break; }
          } else if (rep.IsDouble()) {
            if (!IsNumber(val)) { all_compatible = false; break; }
          } else if (rep.IsHeapObject()) {
            if (IsSmi(val)) { all_compatible = false; break; }
          }
          // Tagged: always compatible
        }
      }
      if (all_compatible) {
        Advance();  // skip '}'
        Handle<JSObject> obj = factory_->NewJSObjectFromMap(feedback);
        {
          DisallowGarbageCollection no_gc;
          Tagged<Map> raw_map = *feedback;
          for (int i = 0; i < nof_descriptors; i++) {
            FieldIndex field_index = FieldIndex::ForDetails(
                raw_map,
                descriptors->GetDetails(InternalIndex(i)));
            obj->FastPropertyAtPut(field_index, *values[i],
                                   SKIP_WRITE_BARRIER);
          }
        }
        // Don't update cache — feedback map is already in the cache
        // (that's how we found it). Redundant insertion causes thrashing
        // in multi-shape workloads.
        return handle_scope.CloseAndEscape(handle(*obj, isolate_));
      }
      // Non-tagged fields — fall through to slow construction.
    }

    // ── Slow fallback ─────────────────────────────────────────────
    // Push matched keys (from descriptors) and remaining keys (from
    // ScanRdnString) onto property_stack_, then build via
    // RdnDataObjectBuilder for optimal map transitions.
    {
      size_t prop_start = property_stack_.size();

      // Push already-matched keys from descriptors (pre-materialized).
      for (int i = 0; i < matched; i++) {
        Handle<String> key(
            Cast<String>(descriptors->GetKey(InternalIndex(i))), isolate_);
        property_stack_.push_back(RdnProperty(key, values[i]));
      }

      // If matched < nof_descriptors, we broke at a ',' and are before '"'.
      // The ',' was already consumed, so parse the remaining key.
      if (matched < nof_descriptors) {
        if (!IsAtEnd() && CurrentChar() == '"') {
          Advance();  // skip opening "
          RdnString key_desc = ScanRdnString(true);
          if (has_error_) {
            property_stack_.resize(prop_start);
            return MaybeHandle<Object>();
          }
          SkipWhitespace();
          if (IsAtEnd() || CurrentChar() != ':') {
            ReportError("Expected ':'");
            property_stack_.resize(prop_start);
            return MaybeHandle<Object>();
          }
          Advance();  // skip ':'
          Handle<Object> val;
          ASSIGN_RETURN_ON_EXCEPTION(isolate_, val, ParseValue());
          property_stack_.push_back(RdnProperty(key_desc, val));
          SkipWhitespace();
        }
      }

      // Parse any remaining properties with deferred keys.
      while (!IsAtEnd() && CurrentChar() == ',') {
        Advance();
        SkipWhitespace();
        if (IsAtEnd() || CurrentChar() != '"') {
          ReportError("Expected string key");
          property_stack_.resize(prop_start);
          return MaybeHandle<Object>();
        }
        Advance();  // skip opening "
        RdnString key_desc = ScanRdnString(true);
        if (has_error_) {
          property_stack_.resize(prop_start);
          return MaybeHandle<Object>();
        }
        SkipWhitespace();
        if (IsAtEnd() || CurrentChar() != ':') {
          ReportError("Expected ':'");
          property_stack_.resize(prop_start);
          return MaybeHandle<Object>();
        }
        Advance();  // skip ':'
        Handle<Object> val;
        ASSIGN_RETURN_ON_EXCEPTION(isolate_, val, ParseValue());
        property_stack_.push_back(RdnProperty(key_desc, val));
        SkipWhitespace();
      }

      if (IsAtEnd() || CurrentChar() != '}') {
        ReportError("Expected '}'");
        property_stack_.resize(prop_start);
        return MaybeHandle<Object>();
      }
      Advance();  // skip '}'

      int count = static_cast<int>(property_stack_.size() - prop_start);
      RdnDataObjectBuilder builder(
          isolate_, HOLEY_ELEMENTS, count, feedback,
          RdnDataObjectBuilder::kHeapNumbersGuaranteedUniquelyOwned);
      RdnNamedPropertyIterator prop_it(
          *this, &property_stack_[prop_start],
          &property_stack_[prop_start] + count);
      Handle<JSObject> obj = builder.BuildFromIterator(prop_it);

      object_map_cache_->set(object_map_cache_next_, obj->map());
      object_map_cache_counts_[object_map_cache_next_] = count;
      object_map_cache_next_ =
          (object_map_cache_next_ + 1) % kObjectMapCacheSize;
      map_cache_populated_ = true;

      property_stack_.resize(prop_start);
      return handle_scope.CloseAndEscape(handle(*obj, isolate_));
    }
  }

slow_fallback_start:
  // Deprecated map — can't use fast path. But cursor is past first key.
  // Materialize first key from descriptor[0] and delegate to
  // FinishObjectMaterialized.
  {
    Handle<String> first_key(
        Cast<String>(descriptors->GetKey(InternalIndex(0))), isolate_);
    SkipWhitespace();
    if (IsAtEnd() || CurrentChar() != ':') {
      ReportError("Expected ':'");
      return MaybeHandle<Object>();
    }
    return FinishObjectMaterialized(first_key);
  }
}

// ── FinishObject (RdnString overload) ─────────────────────────────
// Fast path: first key as deferred RdnString descriptor. Uses property_stack_
// for deferred string materialization, and RdnDataObjectBuilder for optimal
// object construction via pre-computed map transitions.

template <typename Char>
MaybeHandle<Object> RdnParser<Char>::FinishObject(const RdnString& first_key_desc,
                                                   Handle<Map> feedback) {
  HandleScope handle_scope(isolate_);
  Advance();  // skip :

  size_t start = property_stack_.size();

  // Parse first value and push with deferred key.
  Handle<Object> first_val;
  ASSIGN_RETURN_ON_EXCEPTION(isolate_, first_val, ParseValue());
  property_stack_.push_back(RdnProperty(first_key_desc, first_val));
  SkipWhitespace();

  // Parse remaining properties with deferred key materialization.
  while (true) {
    if (IsAtEnd()) {
      ReportError("Unexpected end of input");
      property_stack_.resize(start);
      return MaybeHandle<Object>();
    }
    base::uc32 c = CurrentChar();
    if (c == '}') {
      Advance();
      break;
    }
    if (c != ',') {
      ReportError("Expected ',' or '}'");
      property_stack_.resize(start);
      return MaybeHandle<Object>();
    }
    Advance();
    SkipWhitespace();
    if (IsAtEnd() || CurrentChar() != '"') {
      ReportError("Expected string key");
      property_stack_.resize(start);
      return MaybeHandle<Object>();
    }

    // Deferred key scan — NO MakeString call.
    Advance();  // skip opening "
    RdnString key_desc = ScanRdnString(true);
    if (has_error_) {
      property_stack_.resize(start);
      return MaybeHandle<Object>();
    }

    SkipWhitespace();
    if (IsAtEnd() || CurrentChar() != ':') {
      ReportError("Expected ':'");
      property_stack_.resize(start);
      return MaybeHandle<Object>();
    }
    Advance();  // skip :

    Handle<Object> val;
    ASSIGN_RETURN_ON_EXCEPTION(isolate_, val, ParseValue());
    property_stack_.push_back(RdnProperty(key_desc, val));
    SkipWhitespace();
  }

  int count = static_cast<int>(property_stack_.size() - start);

  // ── kUnknown learning ───────────────────────────────────────────
  // Validate parsed keys against the feedback descriptor array to promote
  // or demote the fast-iterable state for future parses.
  if (!feedback.is_null()) {
    using FastIterableState = DescriptorArray::FastIterableState;
    Handle<DescriptorArray> descriptors(
        feedback->instance_descriptors(), isolate_);
    int nof = feedback->NumberOfOwnDescriptors();

    if (descriptors->fast_iterable() == FastIterableState::kUnknown &&
        nof == count) {
      bool all_fast = true;
      {
        DisallowGarbageCollection no_gc;
        Tagged<DescriptorArray> desc = *descriptors;
        for (int i = 0; i < count; i++) {
          Tagged<Name> property_name = desc->GetKey(InternalIndex(i));

          if (IsSymbol(property_name)) { all_fast = false; break; }

          // Compare raw key chars against descriptor key.
          base::Vector<const Char> key_chars =
              GetKeyChars(property_stack_[start + i].string);
          if (!Cast<String>(property_name)->IsEqualTo(key_chars)) {
            all_fast = false;
            break;
          }

          PropertyDetails details = desc->GetDetails(InternalIndex(i));
          if (details.IsDontEnum() ||
              details.location() != PropertyLocation::kField) {
            all_fast = false;
            break;
          }

          Tagged<String> key_str = Cast<String>(property_name);
          if (!InstanceTypeChecker::IsOneByteString(key_str->map())) {
            all_fast = false;
            break;
          }
        }
      }
      if (all_fast) {
        descriptors->set_fast_iterable_if(FastIterableState::kJsonFast,
                                          FastIterableState::kUnknown);
      } else {
        descriptors->set_fast_iterable(FastIterableState::kJsonSlow);
      }
    }
  }

  // ── Map cache fast path ─────────────────────────────────────────
  // Search the multi-entry map cache for a matching shape. On hit,
  // stamp out properties directly via FastPropertyAtPut (no transitions).
  if (map_cache_populated_) {
    for (int ci = 0; ci < kObjectMapCacheSize; ci++) {
      if (object_map_cache_counts_[ci] != count) continue;
      Tagged<Object> cached_entry = object_map_cache_->get(ci);
      if (!IsMap(cached_entry)) continue;
      Tagged<Map> cached_map = Cast<Map>(cached_entry);
      if (cached_map->NumberOfOwnDescriptors() != count) continue;

      bool keys_match = true;
      bool all_compatible = true;
      {
        DisallowGarbageCollection no_gc;
        Tagged<DescriptorArray> desc = cached_map->instance_descriptors();
        for (int i = 0; i < count; i++) {
          Tagged<Name> expected = desc->GetKey(InternalIndex(i));
          base::Vector<const Char> key_chars =
              GetKeyChars(property_stack_[start + i].string);
          if (!Cast<String>(expected)->IsEqualTo(key_chars)) {
            keys_match = false;
            break;
          }
        }
        if (keys_match) {
          for (int i = 0; i < count; i++) {
            PropertyDetails details = desc->GetDetails(InternalIndex(i));
            if (details.location() != PropertyLocation::kField) {
              all_compatible = false;
              break;
            }
            Representation rep = details.representation();
            Tagged<Object> val = *property_stack_[start + i].value;
            if (rep.IsSmi()) {
              if (!IsSmi(val)) { all_compatible = false; break; }
            } else if (rep.IsDouble()) {
              if (!IsNumber(val)) { all_compatible = false; break; }
            } else if (rep.IsHeapObject()) {
              if (IsSmi(val)) { all_compatible = false; break; }
            }
          }
        }
      }
      if (keys_match && all_compatible) {
        Handle<Map> map_handle(cached_map, isolate_);
        Handle<JSObject> obj = factory_->NewJSObjectFromMap(map_handle);
        {
          DisallowGarbageCollection no_gc;
          Tagged<Map> raw_map = *map_handle;
          for (int i = 0; i < count; i++) {
            FieldIndex field_index = FieldIndex::ForDetails(
                raw_map,
                raw_map->instance_descriptors()->GetDetails(InternalIndex(i)));
            obj->FastPropertyAtPut(field_index,
                                   *property_stack_[start + i].value,
                                   SKIP_WRITE_BARRIER);
          }
        }
        property_stack_.resize(start);
        return handle_scope.CloseAndEscape(handle(*obj, isolate_));
      }
    }
  }

  // ── Builder slow path ───────────────────────────────────────────
  // Use RdnDataObjectBuilder for optimal map transition-based construction.
  // The builder uses GetKeyChars() for fast expected-transition matching and
  // only materializes strings (via GetKey) when needed.
  {
    Handle<Map> expected_map;
    if (!feedback.is_null() && !feedback->is_deprecated()) {
      expected_map = feedback;
    }
    RdnDataObjectBuilder builder(
        isolate_, HOLEY_ELEMENTS, count, expected_map,
        RdnDataObjectBuilder::kHeapNumbersGuaranteedUniquelyOwned);
    RdnNamedPropertyIterator it(
        *this, &property_stack_[start],
        &property_stack_[start] + count);
    Handle<JSObject> obj = builder.BuildFromIterator(it);

    // Update map cache (round-robin).
    object_map_cache_->set(object_map_cache_next_, obj->map());
    object_map_cache_counts_[object_map_cache_next_] = count;
    object_map_cache_next_ =
        (object_map_cache_next_ + 1) % kObjectMapCacheSize;
    map_cache_populated_ = true;

    property_stack_.resize(start);
    return handle_scope.CloseAndEscape(handle(*obj, isolate_));
  }
}

// ── FinishObjectMaterialized ──────────────────────────────────────
// Slow overload for pre-materialized first key (rare paths: ParseBrace
// slow disambiguation, deprecated map fallback). Uses simple AddProperty.

template <typename Char>
MaybeHandle<Object> RdnParser<Char>::FinishObjectMaterialized(
    Handle<String> first_key) {
  HandleScope handle_scope(isolate_);
  Advance();  // skip :

  base::SmallVector<std::pair<Handle<String>, Handle<Object>>, 16> properties;

  Handle<Object> first_val;
  ASSIGN_RETURN_ON_EXCEPTION(isolate_, first_val, ParseValue());
  properties.push_back({first_key, first_val});
  SkipWhitespace();

  while (true) {
    if (IsAtEnd()) {
      ReportError("Unexpected end of input");
      return MaybeHandle<Object>();
    }
    base::uc32 c = CurrentChar();
    if (c == '}') {
      Advance();
      break;
    }
    if (c != ',') {
      ReportError("Expected ',' or '}'");
      return MaybeHandle<Object>();
    }
    Advance();
    SkipWhitespace();
    if (IsAtEnd() || CurrentChar() != '"') {
      ReportError("Expected string key");
      return MaybeHandle<Object>();
    }

    Advance();  // skip opening "
    RdnString key_desc = ScanRdnString(true);
    if (has_error_) return MaybeHandle<Object>();
    Handle<String> key = MakeString(key_desc);

    SkipWhitespace();
    if (IsAtEnd() || CurrentChar() != ':') {
      ReportError("Expected ':'");
      return MaybeHandle<Object>();
    }
    Advance();  // skip :

    Handle<Object> val;
    ASSIGN_RETURN_ON_EXCEPTION(isolate_, val, ParseValue());
    properties.push_back({key, val});
    SkipWhitespace();
  }

  int count = static_cast<int>(properties.size());
  Handle<Map> map = factory_->ObjectLiteralMapFromCache(
      isolate_->native_context(), count);
  Handle<JSObject> obj = factory_->NewJSObjectFromMap(map);

  for (int i = 0; i < count; i++) {
    JSObject::AddProperty(isolate_, obj, properties[i].first,
                          properties[i].second, NONE);
  }

  return handle_scope.CloseAndEscape(handle(*obj, isolate_));
}

// ── Map construction ──────────────────────────────────────────────

template <typename Char>
MaybeHandle<Object> RdnParser<Char>::FinishMap(Handle<Object> first_key) {
  HandleScope handle_scope(isolate_);
  Advance(2);  // skip =>
  DirectHandle<JSMap> map = factory_->NewJSMap();
  Handle<OrderedHashMap> table(
      Cast<OrderedHashMap>(map->table()), isolate_);

  Handle<Object> ikey = first_key;
  if (IsString(*ikey)) {
    ikey = factory_->InternalizeString(Cast<String>(ikey));
  }
  Handle<Object> first_val;
  ASSIGN_RETURN_ON_EXCEPTION(isolate_, first_val, ParseValue());
  table = OrderedHashMap::Add(isolate_, table, ikey, first_val)
              .ToHandleChecked();
  map->set_table(*table);
  SkipWhitespace();

  while (true) {
    if (IsAtEnd()) {
      ReportError("Unexpected end of input");
      return MaybeHandle<Object>();
    }
    base::uc32 c = CurrentChar();
    if (c == '}') {
      Advance();
      return handle_scope.CloseAndEscape(handle(*map, isolate_));
    }
    if (c != ',') {
      ReportError("Expected ',' or '}'");
      return MaybeHandle<Object>();
    }
    Advance();
    Handle<Object> key;
    ASSIGN_RETURN_ON_EXCEPTION(isolate_, key, ParseValue());
    if (IsString(*key)) {
      key = factory_->InternalizeString(Cast<String>(key));
    }
    SkipWhitespace();
    if (IsAtEnd() || CurrentChar() != '=' || Peek(1) != '>') {
      ReportError("Expected '=>'");
      return MaybeHandle<Object>();
    }
    Advance(2);
    Handle<Object> val;
    ASSIGN_RETURN_ON_EXCEPTION(isolate_, val, ParseValue());
    table = handle(Cast<OrderedHashMap>(map->table()), isolate_);
    table = OrderedHashMap::Add(isolate_, table, key, val)
                .ToHandleChecked();
    map->set_table(*table);
    SkipWhitespace();
  }
}

// ── Set construction ──────────────────────────────────────────────

template <typename Char>
MaybeHandle<Object> RdnParser<Char>::FinishSet(Handle<Object> first_value) {
  HandleScope handle_scope(isolate_);
  Advance();  // skip ,
  DirectHandle<JSSet> set = factory_->NewJSSet();
  Handle<OrderedHashSet> table(
      Cast<OrderedHashSet>(set->table()), isolate_);
  Handle<Object> ival = first_value;
  if (IsString(*ival)) {
    ival = factory_->InternalizeString(Cast<String>(ival));
  }
  table = OrderedHashSet::Add(isolate_, table, ival)
              .ToHandleChecked();
  set->set_table(*table);

  while (true) {
    Handle<Object> val;
    ASSIGN_RETURN_ON_EXCEPTION(isolate_, val, ParseValue());
    if (IsString(*val)) {
      val = factory_->InternalizeString(Cast<String>(val));
    }
    table = handle(Cast<OrderedHashSet>(set->table()), isolate_);
    table = OrderedHashSet::Add(isolate_, table, val).ToHandleChecked();
    set->set_table(*table);
    SkipWhitespace();
    if (IsAtEnd()) {
      ReportError("Unexpected end of input");
      return MaybeHandle<Object>();
    }
    base::uc32 c = CurrentChar();
    if (c == '}') {
      Advance();
      return handle_scope.CloseAndEscape(handle(*set, isolate_));
    }
    if (c != ',') {
      ReportError("Expected ',' or '}'");
      return MaybeHandle<Object>();
    }
    Advance();
  }
}

// ── Map{ keyword ──────────────────────────────────────────────────

template <typename Char>
MaybeHandle<Object> RdnParser<Char>::ParseMapKeyword() {
  if (!Match("Map{", 4)) {
    ReportError("Expected 'Map{'");
    return MaybeHandle<Object>();
  }
  Advance(4);
  SkipWhitespace();

  if (!IsAtEnd() && CurrentChar() == '}') {
    Advance();
    return handle(*factory_->NewJSMap(), isolate_);
  }

  Handle<Object> first_key;
  ASSIGN_RETURN_ON_EXCEPTION(isolate_, first_key, ParseValue());
  SkipWhitespace();
  if (IsAtEnd() || CurrentChar() != '=' || Peek(1) != '>') {
    ReportError("Expected '=>'");
    return MaybeHandle<Object>();
  }
  return FinishMap(first_key);
}

// ── Set{ keyword ──────────────────────────────────────────────────

template <typename Char>
MaybeHandle<Object> RdnParser<Char>::ParseSetKeyword() {
  if (!Match("Set{", 4)) {
    ReportError("Expected 'Set{'");
    return MaybeHandle<Object>();
  }
  Advance(4);
  SkipWhitespace();

  if (!IsAtEnd() && CurrentChar() == '}') {
    Advance();
    return handle(*factory_->NewJSSet(), isolate_);
  }

  Handle<Object> first_value;
  ASSIGN_RETURN_ON_EXCEPTION(isolate_, first_value, ParseValue());
  SkipWhitespace();

  if (IsAtEnd()) {
    ReportError("Unexpected end of input");
    return MaybeHandle<Object>();
  }
  base::uc32 c = CurrentChar();
  if (c == '}') {
    Advance();
    DirectHandle<JSSet> set = factory_->NewJSSet();
    Handle<OrderedHashSet> table(
        Cast<OrderedHashSet>(set->table()), isolate_);
    table = OrderedHashSet::Add(isolate_, table, first_value)
                .ToHandleChecked();
    set->set_table(*table);
    return handle(*set, isolate_);
  }
  if (c == ',') {
    return FinishSet(first_value);
  }
  ReportError("Expected ',' or '}'");
  return MaybeHandle<Object>();
}

// ── @datetime / @timeonly / @duration / @unix ──────────────────────

template <typename Char>
MaybeHandle<Object> RdnParser<Char>::ParseDateTime() {
  Advance();  // skip @
  if (IsAtEnd()) {
    ReportError("Unexpected end of input after @");
    return MaybeHandle<Object>();
  }

  // Duration: @P...
  if (CurrentChar() == 'P') return ParseDuration();

  // Read token until delimiter, validating characters
  const Char* start = cursor_;
  while (cursor_ < end_) {
    Char ch = *cursor_;
    if (ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t' ||
        ch == ',' || ch == '}' || ch == ']' || ch == ')') break;
    if (!IsDecimalDigit(ch) && ch != '-' && ch != ':' && ch != '.' &&
        ch != 'T' && ch != 'Z' && ch != '+') {
      ReportError("Invalid character in datetime");
      return MaybeHandle<Object>();
    }
    cursor_++;
  }

  int token_len = static_cast<int>(cursor_ - start);

  // Classify the token
  bool all_digits = true;
  bool has_colon = false;
  bool has_dash = false;
  bool has_T = false;
  bool leading_minus = false;
  int digit_count = 0;

  for (const Char* p = start; p < cursor_; p++) {
    Char ch = *p;
    if (ch >= '0' && ch <= '9') {
      digit_count++;
    } else if (ch == '-') {
      if (p == start) leading_minus = true;
      else { has_dash = true; all_digits = false; }
    } else if (ch == ':') {
      has_colon = true;
      all_digits = false;
    } else if (ch == 'T') {
      has_T = true;
      all_digits = false;
    } else {
      all_digits = false;
    }
  }

  // Build token string
  Handle<String> token;
  if (sizeof(Char) == 1) {
    token = factory_->NewStringFromOneByte(
        base::Vector<const uint8_t>(
            reinterpret_cast<const uint8_t*>(start), token_len))
        .ToHandleChecked();
  } else {
    token = factory_->NewStringFromTwoByte(
        base::Vector<const base::uc16>(
            reinterpret_cast<const base::uc16*>(start), token_len))
        .ToHandleChecked();
  }

  // Unix timestamp: all digits (optionally leading minus)
  if (all_digits && digit_count == token_len - (leading_minus ? 1 : 0)) {
    double num = 0;
    bool negative = false;
    const Char* p = start;
    if (*p == '-') { negative = true; p++; }
    while (p < cursor_) {
      num = num * 10 + (*p - '0');
      p++;
    }
    if (negative) num = -num;
    double ms = (digit_count <= 10) ? num * 1000 : num;
    return MakeDate(ms);
  }

  // Time only: HH:MM:SS or HH:MM:SS.mmm (strict format)
  if (has_colon && !has_dash && !has_T) {
    const Char* p = start;

    // Parse hours: exactly 2 digits
    if (cursor_ - p < 2 || !IsDecimalDigit(p[0]) || !IsDecimalDigit(p[1])) {
      ReportError("Time requires 2-digit hours (HH)");
      return MaybeHandle<Object>();
    }
    int h = (p[0] - '0') * 10 + (p[1] - '0');
    p += 2;

    if (p >= cursor_ || *p != ':') {
      ReportError("Expected ':' after hours");
      return MaybeHandle<Object>();
    }
    p++;

    // Parse minutes: exactly 2 digits
    if (cursor_ - p < 2 || !IsDecimalDigit(p[0]) || !IsDecimalDigit(p[1])) {
      ReportError("Time requires 2-digit minutes (MM)");
      return MaybeHandle<Object>();
    }
    int m = (p[0] - '0') * 10 + (p[1] - '0');
    p += 2;

    int s = 0, ms = 0;
    if (p < cursor_ && *p == ':') {
      p++;
      // Parse seconds: exactly 2 digits
      if (cursor_ - p < 2 || !IsDecimalDigit(p[0]) || !IsDecimalDigit(p[1])) {
        ReportError("Time requires 2-digit seconds (SS)");
        return MaybeHandle<Object>();
      }
      s = (p[0] - '0') * 10 + (p[1] - '0');
      p += 2;

      if (p < cursor_ && *p == '.') {
        p++;
        int ms_digits = 0;
        while (p < cursor_ && ms_digits < 3) {
          if (!IsDecimalDigit(*p)) {
            ReportError("Invalid digit in time milliseconds");
            return MaybeHandle<Object>();
          }
          ms = ms * 10 + (*p - '0');
          p++;
          ms_digits++;
        }
        while (ms_digits < 3) { ms *= 10; ms_digits++; }
      }
    }

    if (p != cursor_) {
      ReportError("Unexpected characters in time value");
      return MaybeHandle<Object>();
    }

    if (h > 23 || m > 59 || s > 59 || ms > 999) {
      ReportError("Time value out of range");
      return MaybeHandle<Object>();
    }

    return MakeTimeOnly(h, m, s, ms);
  }

  // Date only: YYYY-MM-DD (exactly 10 chars)
  if (token_len == 10 && has_dash && !has_T && !has_colon) {
    Handle<String> suffix = factory_->NewStringFromAsciiChecked("T00:00:00Z");
    Handle<String> iso_str =
        factory_->NewConsString(token, suffix).ToHandleChecked();
    iso_str = String::Flatten(isolate_, iso_str);
    double time_val = ParseDateTimeString(isolate_, iso_str);
    if (std::isnan(time_val)) {
      ReportError("Invalid date");
      return MaybeHandle<Object>();
    }
    return MakeDate(time_val);
  }

  // Full ISO datetime
  double time_val = ParseDateTimeString(isolate_, token);
  if (std::isnan(time_val)) {
    ReportError("Invalid date");
    return MaybeHandle<Object>();
  }
  return MakeDate(time_val);
}

template <typename Char>
MaybeHandle<Object> RdnParser<Char>::ParseDuration() {
  const Char* start = cursor_;
  while (cursor_ < end_) {
    Char ch = *cursor_;
    if (ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t' ||
        ch == ',' || ch == '}' || ch == ']' || ch == ')') break;
    // Validate: only duration-valid characters
    if (!IsDecimalDigit(ch) && ch != 'P' && ch != 'Y' && ch != 'M' &&
        ch != 'W' && ch != 'D' && ch != 'T' && ch != 'H' && ch != 'S' &&
        ch != '.') {
      ReportError("Invalid character in duration");
      return MaybeHandle<Object>();
    }
    cursor_++;
  }
  int len = static_cast<int>(cursor_ - start);

  // Must be at least P + digit + designator (e.g. P1D)
  if (len < 3) {
    ReportError("Duration too short");
    return MaybeHandle<Object>();
  }

  // Must have at least one designator letter after P
  bool has_designator = false;
  for (const Char* p = start + 1; p < cursor_; p++) {
    Char ch = *p;
    if (ch == 'Y' || ch == 'M' || ch == 'W' || ch == 'D' ||
        ch == 'H' || ch == 'S') {
      has_designator = true;
      break;
    }
  }
  if (!has_designator) {
    ReportError("Duration must have at least one designator (Y/M/W/D/H/S)");
    return MaybeHandle<Object>();
  }

  Handle<String> iso;
  if (sizeof(Char) == 1) {
    iso = factory_->NewStringFromOneByte(
        base::Vector<const uint8_t>(
            reinterpret_cast<const uint8_t*>(start), len))
        .ToHandleChecked();
  } else {
    iso = factory_->NewStringFromTwoByte(
        base::Vector<const base::uc16>(
            reinterpret_cast<const base::uc16*>(start), len))
        .ToHandleChecked();
  }
  return MakeDuration(iso);
}

// ── Regex parsing ─────────────────────────────────────────────────

template <typename Char>
MaybeHandle<Object> RdnParser<Char>::ParseRegex() {
  Advance();  // skip opening /
  std::vector<base::uc16> pattern_chars;
  bool escaped = false;

  while (cursor_ < end_) {
    Char c = *cursor_;
    if (escaped) {
      pattern_chars.push_back(static_cast<base::uc16>(c));
      escaped = false;
      cursor_++;
      continue;
    }
    if (c == '\\') {
      pattern_chars.push_back('\\');
      escaped = true;
      cursor_++;
      continue;
    }
    if (c == '/') {
      cursor_++;
      v8::RegExp::Flags flags = v8::RegExp::kNone;
      while (cursor_ < end_) {
        Char fc = *cursor_;
        if (fc == 'g') { flags = static_cast<v8::RegExp::Flags>(flags | v8::RegExp::kGlobal); }
        else if (fc == 'i') { flags = static_cast<v8::RegExp::Flags>(flags | v8::RegExp::kIgnoreCase); }
        else if (fc == 'm') { flags = static_cast<v8::RegExp::Flags>(flags | v8::RegExp::kMultiline); }
        else if (fc == 's') { flags = static_cast<v8::RegExp::Flags>(flags | v8::RegExp::kDotAll); }
        else if (fc == 'u') { flags = static_cast<v8::RegExp::Flags>(flags | v8::RegExp::kUnicode); }
        else if (fc == 'y') { flags = static_cast<v8::RegExp::Flags>(flags | v8::RegExp::kSticky); }
        else if (fc == 'd') { flags = static_cast<v8::RegExp::Flags>(flags | v8::RegExp::kHasIndices); }
        else if (fc == 'v') { flags = static_cast<v8::RegExp::Flags>(flags | v8::RegExp::kUnicodeSets); }
        else {
          if ((fc >= 'a' && fc <= 'z') || (fc >= 'A' && fc <= 'Z')) {
            ReportError("Unknown regex flag");
            return MaybeHandle<Object>();
          }
          break;
        }
        cursor_++;
      }

      Handle<String> pattern_str;
      if (pattern_chars.empty()) {
        pattern_str = factory_->empty_string();
      } else {
        bool is_one_byte = true;
        for (base::uc16 ch : pattern_chars) {
          if (ch > 0xFF) { is_one_byte = false; break; }
        }
        if (is_one_byte) {
          std::vector<uint8_t> one_byte(pattern_chars.size());
          for (size_t i = 0; i < pattern_chars.size(); i++) {
            one_byte[i] = static_cast<uint8_t>(pattern_chars[i]);
          }
          pattern_str = factory_->NewStringFromOneByte(
              base::Vector<const uint8_t>(one_byte.data(),
                                          static_cast<int>(one_byte.size())))
              .ToHandleChecked();
        } else {
          pattern_str = factory_->NewStringFromTwoByte(
              base::Vector<const base::uc16>(
                  pattern_chars.data(),
                  static_cast<int>(pattern_chars.size())))
              .ToHandleChecked();
        }
      }

      JSRegExp::Flags internal_flags = static_cast<JSRegExp::Flags>(flags);
      MaybeDirectHandle<JSRegExp> result =
          JSRegExp::New(isolate_, pattern_str, internal_flags);
      if (result.is_null()) {
        ReportError("Invalid regex");
        return MaybeHandle<Object>();
      }
      return handle(*result.ToHandleChecked(), isolate_);
    }
    pattern_chars.push_back(static_cast<base::uc16>(c));
    cursor_++;
  }

  ReportError("Unterminated regex");
  return MaybeHandle<Object>();
}

// ── Binary base64: b"..." ─────────────────────────────────────────

template <typename Char>
MaybeHandle<Object> RdnParser<Char>::ParseBinaryB64() {
  if (Peek(1) != '"') {
    ReportError("Expected 'b\"'");
    return MaybeHandle<Object>();
  }
  Advance();  // skip b
  Handle<Object> encoded_obj;
  ASSIGN_RETURN_ON_EXCEPTION(isolate_, encoded_obj, ParseString());
  Handle<String> encoded = Cast<String>(encoded_obj);

  int str_len = encoded->length();
  int decoded_len = (str_len * 3) / 4;
  std::vector<uint8_t> decoded(decoded_len + 4);

  static const int8_t b64_table[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  };

  encoded = String::Flatten(isolate_, encoded);
  DisallowGarbageCollection no_gc;
  int out_pos = 0;
  uint32_t accum = 0;
  int bits = 0;

  for (int i = 0; i < str_len; i++) {
    uint16_t ch = encoded->Get(i);
    if (ch == '=') continue;
    if (ch > 255 || b64_table[ch] < 0) {
      AllowGarbageCollection allow_gc2;
      ReportError("Invalid base64 character");
      return MaybeHandle<Object>();
    }
    int8_t val = b64_table[ch];
    accum = (accum << 6) | val;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      decoded[out_pos++] = static_cast<uint8_t>((accum >> bits) & 0xFF);
    }
  }

  int actual_len = out_pos;
  AllowGarbageCollection allow_gc;

  Handle<JSArrayBuffer> buffer;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate_, buffer,
      factory_->NewJSArrayBufferAndBackingStore(
          actual_len, InitializedFlag::kUninitialized));
  if (actual_len > 0) {
    memcpy(buffer->backing_store(), decoded.data(), actual_len);
  }
  return factory_->NewJSTypedArray(kExternalUint8Array, buffer, 0, actual_len);
}

// ── Binary hex: x"..." ────────────────────────────────────────────

template <typename Char>
MaybeHandle<Object> RdnParser<Char>::ParseBinaryHex() {
  if (Peek(1) != '"') {
    ReportError("Expected 'x\"'");
    return MaybeHandle<Object>();
  }
  Advance();  // skip x
  Handle<Object> encoded_obj;
  ASSIGN_RETURN_ON_EXCEPTION(isolate_, encoded_obj, ParseString());
  Handle<String> encoded = Cast<String>(encoded_obj);

  int str_len = encoded->length();
  if (str_len % 2 != 0) {
    ReportError("Hex string must have even length");
    return MaybeHandle<Object>();
  }
  int byte_len = str_len / 2;

  std::vector<uint8_t> decoded(byte_len);
  encoded = String::Flatten(isolate_, encoded);
  DisallowGarbageCollection no_gc;

  auto is_hex_digit = [](uint16_t c) -> bool {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
  };
  auto hex_val = [](uint16_t c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
  };

  for (int i = 0; i < byte_len; i++) {
    uint16_t hi = encoded->Get(i * 2);
    uint16_t lo = encoded->Get(i * 2 + 1);
    if (!is_hex_digit(hi) || !is_hex_digit(lo)) {
      AllowGarbageCollection allow_gc2;
      ReportError("Invalid hex character");
      return MaybeHandle<Object>();
    }
    decoded[i] = static_cast<uint8_t>((hex_val(hi) << 4) | hex_val(lo));
  }

  AllowGarbageCollection allow_gc;

  Handle<JSArrayBuffer> buffer;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate_, buffer,
      factory_->NewJSArrayBufferAndBackingStore(
          byte_len, InitializedFlag::kUninitialized));
  if (byte_len > 0) {
    memcpy(buffer->backing_store(), decoded.data(), byte_len);
  }
  return factory_->NewJSTypedArray(kExternalUint8Array, buffer, 0, byte_len);
}

// ── Helper: create Date ───────────────────────────────────────────

template <typename Char>
MaybeHandle<Object> RdnParser<Char>::MakeDate(double time_ms) {
  DirectHandle<JSFunction> date_ctor(isolate_->date_function());
  MaybeDirectHandle<JSDate> date =
      JSDate::New(isolate_, date_ctor, date_ctor, time_ms);
  if (date.is_null()) {
    ReportError("Invalid date value");
    return MaybeHandle<Object>();
  }
  return handle(*date.ToHandleChecked(), isolate_);
}

// ── Helper: create TimeOnly as plain object ────────────────────────

template <typename Char>
MaybeHandle<Object> RdnParser<Char>::MakeTimeOnly(int h, int m, int s,
                                                   int ms) {
  Handle<JSObject> obj = factory_->NewJSObject(isolate_->object_function());
  Handle<String> hours_key = factory_->NewStringFromAsciiChecked("hours");
  Handle<String> minutes_key = factory_->NewStringFromAsciiChecked("minutes");
  Handle<String> seconds_key = factory_->NewStringFromAsciiChecked("seconds");
  Handle<String> ms_key = factory_->NewStringFromAsciiChecked("milliseconds");

  JSObject::AddProperty(isolate_, obj, hours_key,
                        handle(Smi::FromInt(h), isolate_), NONE);
  JSObject::AddProperty(isolate_, obj, minutes_key,
                        handle(Smi::FromInt(m), isolate_), NONE);
  JSObject::AddProperty(isolate_, obj, seconds_key,
                        handle(Smi::FromInt(s), isolate_), NONE);
  JSObject::AddProperty(isolate_, obj, ms_key,
                        handle(Smi::FromInt(ms), isolate_), NONE);

  Handle<String> type_key = factory_->NewStringFromAsciiChecked("__type__");
  Handle<String> type_val = factory_->NewStringFromAsciiChecked("TimeOnly");
  JSObject::AddProperty(isolate_, obj, type_key, type_val, DONT_ENUM);

  return obj;
}

// ── Helper: create Duration as plain object ────────────────────────

template <typename Char>
MaybeHandle<Object> RdnParser<Char>::MakeDuration(Handle<String> iso) {
  Handle<JSObject> obj = factory_->NewJSObject(isolate_->object_function());
  Handle<String> iso_key = factory_->NewStringFromAsciiChecked("iso");
  JSObject::AddProperty(isolate_, obj, iso_key, iso, NONE);

  Handle<String> type_key = factory_->NewStringFromAsciiChecked("__type__");
  Handle<String> type_val = factory_->NewStringFromAsciiChecked("Duration");
  JSObject::AddProperty(isolate_, obj, type_key, type_val, DONT_ENUM);

  return obj;
}

// ── Template instantiations ───────────────────────────────────────

template class RdnParser<uint8_t>;
template class RdnParser<uint16_t>;

}  // namespace internal
}  // namespace v8
