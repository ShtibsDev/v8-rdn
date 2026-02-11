// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// RDN stringifier — converts V8 values to RDN text format.
// Ported from json-stringifier.cc with direct buffer management,
// escape lookup tables, SWAR NeedsEscape, ElementsKind-aware array
// serialization, fast object serialization, and circular reference detection.

#include "src/json/rdn-stringifier.h"

#include <cmath>
#include <string_view>

#include "src/base/strings.h"
#include "src/common/assert-scope.h"
#include "src/execution/isolate.h"
#include "src/heap/factory.h"
#include "src/numbers/conversions.h"
#include "src/objects/bigint.h"
#include "src/objects/elements-kind.h"
#include "src/objects/fixed-array-inl.h"
#include "src/objects/heap-number-inl.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/js-collection-inl.h"
#include "src/objects/js-objects.h"
#include "src/objects/js-regexp-inl.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/ordered-hash-table.h"
#include "src/objects/smi.h"
#include "src/execution/protectors-inl.h"
#include "src/strings/string-builder-inl.h"

#include "hwy/highway.h"

namespace v8 {
namespace internal {

namespace {

// ── Base64 encoding table ──────────────────────────────────────────

static const char kBase64Table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// ── Escape table (from json-stringifier.cc) ────────────────────────
// Translation table to escape Latin1 characters.
// Table entries start at a multiple of 8 and are null-terminated.
constexpr int kRdnEscapeTableEntrySize = 8;
constexpr const char* const RdnEscapeTable =
    "\\u0000\0 \\u0001\0 \\u0002\0 \\u0003\0 "
    "\\u0004\0 \\u0005\0 \\u0006\0 \\u0007\0 "
    "\\b\0     \\t\0     \\n\0     \\u000b\0 "
    "\\f\0     \\r\0     \\u000e\0 \\u000f\0 "
    "\\u0010\0 \\u0011\0 \\u0012\0 \\u0013\0 "
    "\\u0014\0 \\u0015\0 \\u0016\0 \\u0017\0 "
    "\\u0018\0 \\u0019\0 \\u001a\0 \\u001b\0 "
    "\\u001c\0 \\u001d\0 \\u001e\0 \\u001f\0 "
    " \0      !\0      \\\"\0     #\0      "
    "$\0      %\0      &\0      '\0      "
    "(\0      )\0      *\0      +\0      "
    ",\0      -\0      .\0      /\0      "
    "0\0      1\0      2\0      3\0      "
    "4\0      5\0      6\0      7\0      "
    "8\0      9\0      :\0      ;\0      "
    "<\0      =\0      >\0      ?\0      "
    "@\0      A\0      B\0      C\0      "
    "D\0      E\0      F\0      G\0      "
    "H\0      I\0      J\0      K\0      "
    "L\0      M\0      N\0      O\0      "
    "P\0      Q\0      R\0      S\0      "
    "T\0      U\0      V\0      W\0      "
    "X\0      Y\0      Z\0      [\0      "
    "\\\\\0     ]\0      ^\0      _\0      ";

// Do-not-escape flag table: true for chars that need no escaping.
constexpr bool RdnDoNotEscapeFlagTable[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
};

template <typename Char>
constexpr bool DoNotEscape(Char c);

template <>
constexpr bool DoNotEscape(uint8_t c) {
  return RdnDoNotEscapeFlagTable[c];
}

template <>
constexpr bool DoNotEscape(uint16_t c) {
  return (c >= 0x20 && c <= 0x21) ||
         (c >= 0x23 && c != 0x5C && (c < 0xD800 || c > 0xDFFF));
}

// Checks if characters need escaping in a packed input (4 bytes in uint32_t).
constexpr bool NeedsEscape(uint32_t input) {
  constexpr uint32_t mask_0x20 = 0x20202020u;
  constexpr uint32_t mask_0x22 = 0x22222222u;
  constexpr uint32_t mask_0x5c = 0x5C5C5C5Cu;
  constexpr uint32_t mask_0x01 = 0x01010101u;
  constexpr uint32_t mask_msb = 0x80808080u;
  const uint32_t has_lt_0x20 = input - mask_0x20;
  const uint32_t has_0x22 = (input ^ mask_0x22) - mask_0x01;
  const uint32_t has_0x5c = (input ^ mask_0x5c) - mask_0x01;
  const uint32_t result_mask = ~input & mask_msb;
  const uint32_t result = ((has_lt_0x20 | has_0x22 | has_0x5c) & result_mask);
  return result != 0;
}

// Whole-string escape check using SWAR. Scans 4 bytes at a time and returns
// early on the first escape character.
V8_CLANG_NO_SANITIZE("alignment")
bool DoNotEscapeString(const uint8_t* chars, size_t length) {
  using PackedT = uint32_t;
  static constexpr size_t stride = sizeof(PackedT);
  size_t i = 0;
  for (; i + (stride - 1) < length; i += stride) {
    PackedT packed = *reinterpret_cast<const PackedT*>(chars + i);
    if (V8_UNLIKELY(NeedsEscape(packed))) return false;
  }
  for (; i < length; i++) {
    if (!DoNotEscape(chars[i])) return false;
  }
  return true;
}

V8_INLINE bool CanFastSerializeJSObject(Tagged<JSObject> raw_object,
                                        Isolate* isolate) {
  DisallowGarbageCollection no_gc;
  if (IsCustomElementsReceiverMap(raw_object->map())) return false;
  if (!raw_object->HasFastProperties()) return false;
  auto roots = ReadOnlyRoots(isolate);
  auto elements = raw_object->elements();
  return elements == roots.empty_fixed_array() ||
         elements == roots.empty_slow_element_dictionary();
}

// ── RDN Stringifier class ──────────────────────────────────────────
// Direct buffer management ported from JsonStringifier.

class RdnStringifier {
 public:
  explicit RdnStringifier(Isolate* isolate);

  ~RdnStringifier() {
    if (one_byte_ptr_ != one_byte_array_) delete[] one_byte_ptr_;
    if (two_byte_ptr_) delete[] two_byte_ptr_;
  }

  MaybeHandle<Object> Stringify(Handle<Object> value) {
    if (IsUndefined(*value, isolate_) || IsJSFunction(*value) ||
        IsSymbol(*value)) {
      return isolate_->factory()->undefined_value();
    }
    if (!SerializeValue(value)) return MaybeHandle<Object>();
    if (overflowed_ || current_index_ > String::kMaxLength) {
      THROW_NEW_ERROR(isolate_, NewInvalidStringLengthError());
    }
    if (encoding_ == String::ONE_BYTE_ENCODING) {
      return isolate_->factory()
          ->NewStringFromOneByte(base::OneByteVector(
              reinterpret_cast<char*>(one_byte_ptr_), current_index_))
          .ToHandleChecked();
    } else {
      return isolate_->factory()->NewStringFromTwoByte(
          base::Vector<const base::uc16>(two_byte_ptr_, current_index_));
    }
  }

 private:
  // ── Buffer management (ported from JsonStringifier) ──────────────

  template <typename SrcChar, typename DestChar>
  V8_INLINE void Append(SrcChar c) {
    DCHECK_EQ(encoding_ == String::ONE_BYTE_ENCODING, sizeof(DestChar) == 1);
    if (sizeof(DestChar) == 1) {
      one_byte_ptr_[current_index_++] = c;
    } else {
      two_byte_ptr_[current_index_++] =
          static_cast<std::make_unsigned_t<SrcChar>>(c);
    }
    if V8_UNLIKELY (current_index_ == part_length_) Extend();
  }

  V8_INLINE void AppendCharacter(uint8_t c) {
    if (encoding_ == String::ONE_BYTE_ENCODING) {
      Append<uint8_t, uint8_t>(c);
    } else {
      Append<uint8_t, base::uc16>(c);
    }
  }

  template <size_t N>
  V8_INLINE void AppendCStringLiteral(const char (&literal)[N]) {
    constexpr size_t length = N - 1;
    static_assert(length > 0);
    if (length == 1) return AppendCharacter(literal[0]);
    if (encoding_ == String::ONE_BYTE_ENCODING && CurrentPartCanFit(N)) {
      const uint8_t* chars = reinterpret_cast<const uint8_t*>(literal);
      CopyChars<uint8_t, uint8_t>(one_byte_ptr_ + current_index_, chars,
                                  length);
      current_index_ += length;
      if (current_index_ == part_length_) Extend();
      return;
    }
    return AppendCString(literal);
  }

  template <typename SrcChar>
  V8_INLINE void AppendCString(const SrcChar* s) {
    if (encoding_ == String::ONE_BYTE_ENCODING) {
      while (*s != '\0') Append<SrcChar, uint8_t>(*s++);
    } else {
      while (*s != '\0') Append<SrcChar, base::uc16>(*s++);
    }
  }

  template <typename SrcChar>
  V8_INLINE void AppendStringView(std::basic_string_view<SrcChar> s) {
    if (encoding_ == String::ONE_BYTE_ENCODING) {
      for (SrcChar c : s) Append<SrcChar, uint8_t>(c);
    } else {
      for (SrcChar c : s) Append<SrcChar, base::uc16>(c);
    }
  }

  V8_INLINE bool CurrentPartCanFit(size_t length) {
    return part_length_ - current_index_ > length;
  }

  V8_INLINE bool EscapedLengthIfCurrentPartFits(size_t length) {
    if (length > kMaxPartLength) return false;
    static_assert(kMaxPartLength <= (String::kMaxLength >> 3));
    return CurrentPartCanFit(length << 3);
  }

  template <typename SrcChar>
  V8_NOINLINE void AppendSubstring(const SrcChar* src, size_t from, size_t to) {
    if (from == to) return;
    DCHECK_LT(from, to);
    size_t count = to - from;
    while (!CurrentPartCanFit(count + 1)) {
      Extend();
      if (V8_UNLIKELY(overflowed_)) return;
    }
    if (encoding_ == String::ONE_BYTE_ENCODING) {
      if (sizeof(SrcChar) == 1) {
        CopyChars<SrcChar, uint8_t>(one_byte_ptr_ + current_index_, src + from,
                                    count);
      } else {
        ChangeEncoding();
        CopyChars<SrcChar, base::uc16>(two_byte_ptr_ + current_index_,
                                       src + from, count);
      }
    } else {
      CopyChars<SrcChar, base::uc16>(two_byte_ptr_ + current_index_,
                                     src + from, count);
    }
    current_index_ += count;
    DCHECK_LE(current_index_, part_length_);
  }

  V8_NOINLINE void AppendString(Handle<String> string_handle) {
    {
      DisallowGarbageCollection no_gc;
      Tagged<String> string = *string_handle;
      const bool representation_ok =
          encoding_ == String::TWO_BYTE_ENCODING ||
          (string->IsFlat() &&
           String::IsOneByteRepresentationUnderneath(string));
      if (representation_ok) {
        size_t length = string->length();
        while (!CurrentPartCanFit(length + 1)) {
          Extend();
          if (V8_UNLIKELY(overflowed_)) return;
        }
        DCHECK(encoding_ == String::TWO_BYTE_ENCODING ||
               (string->IsFlat() &&
                String::IsOneByteRepresentationUnderneath(string)));
        DCHECK(CurrentPartCanFit(length + 1));
        if (encoding_ == String::ONE_BYTE_ENCODING) {
          CopyChars<uint8_t, uint8_t>(
              one_byte_ptr_ + current_index_,
              string->GetCharVector<uint8_t>(no_gc).begin(), length);
        } else {
          if (String::IsOneByteRepresentationUnderneath(string)) {
            CopyChars<uint8_t, uint16_t>(
                two_byte_ptr_ + current_index_,
                string->GetCharVector<uint8_t>(no_gc).begin(), length);
          } else {
            CopyChars<uint16_t, uint16_t>(
                two_byte_ptr_ + current_index_,
                string->GetCharVector<uint16_t>(no_gc).begin(), length);
          }
        }
        current_index_ += length;
        DCHECK(current_index_ <= part_length_);
        return;
      }
    }
    // Two-byte string but we're in one-byte mode: serialize with escaping.
    SerializeStringValue(string_handle);
  }

  V8_NOINLINE void Extend();
  V8_NOINLINE void ChangeEncoding();

  // ── Circular reference detection ─────────────────────────────────

  enum Result { SUCCESS, EXCEPTION };

  Result StackPush(Handle<Object> object) {
    ++stack_nesting_level_;
    if V8_LIKELY (!need_stack_) {
      if V8_UNLIKELY (stack_nesting_level_ > 10) {
        need_stack_ = true;
        // Switch to stack mode for circular reference detection.
      } else {
        return SUCCESS;
      }
    }
    StackLimitCheck check(isolate_);
    if (check.HasOverflowed()) {
      isolate_->StackOverflow();
      return EXCEPTION;
    }
    {
      DisallowGarbageCollection no_gc;
      Tagged<Object> raw_obj = *object;
      for (size_t i = 0; i < stack_.size(); ++i) {
        if (*stack_[i] == raw_obj) {
          AllowGarbageCollection allow_to_return_error;
          Handle<String> msg =
              isolate_->factory()->NewStringFromAsciiChecked(
                  "Converting circular structure to RDN");
          DirectHandle<Object> error = isolate_->factory()->NewTypeError(
              MessageTemplate::kCircularStructure, msg);
          isolate_->Throw(*error);
          return EXCEPTION;
        }
      }
    }
    stack_.push_back(object);
    return SUCCESS;
  }

  void StackPop() {
    --stack_nesting_level_;
    if V8_LIKELY (!need_stack_) {
      return;
    }
    if (!stack_.empty()) {
      stack_.pop_back();
    }
    if (stack_.empty()) {
      need_stack_ = false;
    }
  }

  // ── NoExtendBuilder for fast-path string serialization ───────────

  template <typename DestChar>
  class NoExtendBuilder {
   public:
    NoExtendBuilder(DestChar* start, size_t* current_index)
        : current_index_(current_index), start_(start), cursor_(start) {}
    ~NoExtendBuilder() { *current_index_ += cursor_ - start_; }

    V8_INLINE void Append(DestChar c) { *(cursor_++) = c; }
    V8_INLINE void AppendCString(const char* s) {
      const uint8_t* u = reinterpret_cast<const uint8_t*>(s);
      while (*u != '\0') Append(*(u++));
    }

    template <typename SrcChar>
    V8_INLINE void AppendSubstring(const SrcChar* src, size_t from, size_t to) {
      if (from == to) return;
      size_t count = to - from;
      CopyChars(cursor_, src + from, count);
      cursor_ += count;
    }

   private:
    size_t* current_index_;
    DestChar* start_;
    DestChar* cursor_;
  };

  // ── Serialization methods ────────────────────────────────────────

  bool SerializeValue(Handle<Object> object);
  bool SerializeSmi(Tagged<Smi> smi);
  bool SerializeDouble(double value);
  bool SerializeHeapNumber(Handle<HeapNumber> number);
  bool SerializeBigInt(Handle<BigInt> bigint);
  bool SerializeStringValue(Handle<String> string);
  bool SerializeJSArray(Handle<JSArray> array);
  bool SerializeJSObject(Handle<JSObject> object);
  bool SerializeJSObjectSlow(Handle<JSObject> object);
  bool SerializeJSDate(Handle<JSDate> date);
  bool SerializeJSRegExp(Handle<JSRegExp> regexp);
  bool SerializeJSMap(Handle<JSMap> map);
  bool SerializeJSSet(Handle<JSSet> set);
  bool SerializeJSTypedArray(Handle<JSTypedArray> array);
  bool SerializeTimeOnly(Handle<JSObject> object);
  bool SerializeDuration(Handle<JSObject> object);

  bool IsTimeOnly(Handle<JSObject> object);
  bool IsDuration(Handle<JSObject> object);

  // String serialization with escape table + SIMD/SWAR/Scalar (ported from
  // JsonStringifier with Highway SIMD scanning).
  template <typename SrcChar, typename DestChar>
  void SerializeStringUnchecked(base::Vector<const SrcChar> src,
                                NoExtendBuilder<DestChar>* dest);

  // SIMD/SWAR/Scalar string escaping (one-byte only)
  template <typename DestChar>
  void SerializeStringUncheckedSIMD(const uint8_t* chars, size_t length,
                                    NoExtendBuilder<DestChar>* dest);

  template <typename DestChar>
  void SerializeStringUncheckedSWAR(const uint8_t* chars, size_t length,
                                    size_t start, size_t uncopied_src_index,
                                    NoExtendBuilder<DestChar>* dest);

  template <typename DestChar>
  void SerializeStringUncheckedScalar(const uint8_t* chars, size_t length,
                                      size_t start, size_t uncopied_src_index,
                                      NoExtendBuilder<DestChar>* dest);

  template <typename SrcChar, typename DestChar>
  void SerializeStringChecked(Tagged<String> string,
                              const DisallowGarbageCollection& no_gc);

  // ── SimplePropertyKeyCache (ported from json-stringifier.cc) ─────
  // 64-entry hash table caching internalized one-byte keys that need no
  // escaping. Cleared on GC since strings can relocate.
  class SimplePropertyKeyCache {
   public:
    explicit SimplePropertyKeyCache(Isolate* isolate) : isolate_(isolate) {
      Clear();
      isolate->main_thread_local_heap()->AddGCEpilogueCallback(UpdatePointersCallback, this);
    }

    ~SimplePropertyKeyCache() {
      isolate_->main_thread_local_heap()->RemoveGCEpilogueCallback(UpdatePointersCallback, this);
    }

    void TryInsert(Tagged<String> string) {
      ReadOnlyRoots roots(isolate_);
      if (string->map() == roots.internalized_one_byte_string_map()) {
        keys_[GetIndex(string)] = MaybeCompress(string);
      }
    }

    bool Contains(Tagged<String> string) {
      return keys_[GetIndex(string)] == MaybeCompress(string);
    }

   private:
    size_t GetIndex(Tagged<String> string) {
      return (string.ptr() >> 4) & kIndexMask;
    }

    Tagged_t MaybeCompress(Tagged<String> string) {
      return COMPRESS_POINTERS_BOOL
                 ? V8HeapCompressionScheme::CompressObject(string.ptr())
                 : static_cast<Tagged_t>(string.ptr());
    }

    void Clear() { MemsetTagged(keys_, Smi::zero(), kSize); }

    static void UpdatePointersCallback(void* cache) {
      reinterpret_cast<SimplePropertyKeyCache*>(cache)->Clear();
    }

    static constexpr size_t kSizeBits = 6;
    static constexpr size_t kSize = 1 << kSizeBits;
    static constexpr size_t kIndexMask = kSize - 1;

    Isolate* isolate_;
    Tagged_t keys_[kSize];
  };

  // Fast-path property key serialization: if the key is cached (internalized
  // one-byte, no escaping needed), emit "key": directly via memcpy.
  template <typename DestChar>
  bool TrySerializeSimplePropertyKey(Tagged<String> key, const DisallowGarbageCollection& no_gc) {
    ReadOnlyRoots roots(isolate_);
    if (key->map() != roots.internalized_one_byte_string_map()) return false;
    if (!key_cache_.Contains(key)) return false;
    size_t length = key->length();
    size_t copy_length = length;
    if constexpr (sizeof(DestChar) == 1) {
      constexpr int kRounding = 4;
      static_assert(kRounding <= kObjectAlignment);
      copy_length = RoundUp(length, kRounding);
    }
    size_t required_length = copy_length + 3;  // " + key + " + :
    if (!CurrentPartCanFit(required_length)) return false;
    NoExtendBuilder<DestChar> no_extend(reinterpret_cast<DestChar*>(part_ptr_) + current_index_, &current_index_);
    no_extend.Append('"');
    base::Vector<const uint8_t> chars(Cast<SeqOneByteString>(key)->GetChars(no_gc), copy_length);
    no_extend.AppendSubstring(chars.begin(), 0, length);
    no_extend.Append('"');
    no_extend.Append(':');
    return true;
  }

  // ── State ────────────────────────────────────────────────────────

  static constexpr size_t kInitialPartLength = 2048;
  static constexpr size_t kMaxPartLength = 16 * 1024;
  static constexpr size_t kPartLengthGrowthFactor = 2;

  Isolate* isolate_;
  Factory* factory_;
  String::Encoding encoding_;
  uint8_t* one_byte_ptr_;
  base::uc16* two_byte_ptr_;
  void* part_ptr_;
  size_t part_length_;
  size_t current_index_;
  bool overflowed_;

  // Circular reference detection.
  int stack_nesting_level_;
  bool need_stack_;
  std::vector<Handle<Object>> stack_;

  // Property key cache for fast repeated key serialization.
  SimplePropertyKeyCache key_cache_;

  // Lazy-initialized internalized strings for TimeOnly/Duration detection.
  // Only allocated when we actually encounter a candidate time type object.
  bool time_strings_initialized_ = false;
  Handle<String> type_key_;       // "__type__"
  Handle<String> time_only_str_;  // "TimeOnly"
  Handle<String> duration_str_;   // "Duration"
  Handle<String> hours_key_;      // "hours"
  Handle<String> minutes_key_;    // "minutes"
  Handle<String> seconds_key_;    // "seconds"
  Handle<String> ms_key_;         // "milliseconds"
  Handle<String> iso_key_;        // "iso"

  void EnsureTimeTypeStringsInitialized() {
    if (time_strings_initialized_) return;
    time_strings_initialized_ = true;
    type_key_ = factory_->InternalizeUtf8String("__type__");
    time_only_str_ = factory_->InternalizeUtf8String("TimeOnly");
    duration_str_ = factory_->InternalizeUtf8String("Duration");
    hours_key_ = factory_->InternalizeUtf8String("hours");
    minutes_key_ = factory_->InternalizeUtf8String("minutes");
    seconds_key_ = factory_->InternalizeUtf8String("seconds");
    ms_key_ = factory_->InternalizeUtf8String("milliseconds");
    iso_key_ = factory_->InternalizeUtf8String("iso");
  }

  uint8_t one_byte_array_[kInitialPartLength];
};

// ── Constructor ────────────────────────────────────────────────────

RdnStringifier::RdnStringifier(Isolate* isolate)
    : isolate_(isolate),
      factory_(isolate->factory()),
      encoding_(String::ONE_BYTE_ENCODING),
      two_byte_ptr_(nullptr),
      part_length_(kInitialPartLength),
      current_index_(0),
      overflowed_(false),
      stack_nesting_level_(0),
      need_stack_(false),
      stack_(),
      key_cache_(isolate) {
  one_byte_ptr_ = one_byte_array_;
  part_ptr_ = one_byte_ptr_;
}

// ── Extend / ChangeEncoding ────────────────────────────────────────

void RdnStringifier::Extend() {
  if (part_length_ >= String::kMaxLength) {
    current_index_ = 0;
    overflowed_ = true;
    return;
  }
  part_length_ *= kPartLengthGrowthFactor;
  if (encoding_ == String::ONE_BYTE_ENCODING) {
    uint8_t* tmp_ptr = new uint8_t[part_length_];
    memcpy(tmp_ptr, one_byte_ptr_, current_index_);
    if (one_byte_ptr_ != one_byte_array_) delete[] one_byte_ptr_;
    one_byte_ptr_ = tmp_ptr;
    part_ptr_ = one_byte_ptr_;
  } else {
    base::uc16* tmp_ptr = new base::uc16[part_length_];
    for (size_t i = 0; i < current_index_; i++) {
      tmp_ptr[i] = two_byte_ptr_[i];
    }
    delete[] two_byte_ptr_;
    two_byte_ptr_ = tmp_ptr;
    part_ptr_ = two_byte_ptr_;
  }
}

void RdnStringifier::ChangeEncoding() {
  encoding_ = String::TWO_BYTE_ENCODING;
  two_byte_ptr_ = new base::uc16[part_length_];
  for (size_t i = 0; i < current_index_; i++) {
    two_byte_ptr_[i] = one_byte_ptr_[i];
  }
  part_ptr_ = two_byte_ptr_;
  if (one_byte_ptr_ != one_byte_array_) delete[] one_byte_ptr_;
  one_byte_ptr_ = nullptr;
}

// ── Type dispatch ──────────────────────────────────────────────────

bool RdnStringifier::SerializeValue(Handle<Object> object) {
  if (IsNull(*object, isolate_) || IsUndefined(*object, isolate_)) {
    AppendCStringLiteral("null");
    return true;
  }

  if (IsSmi(*object)) {
    return SerializeSmi(Cast<Smi>(*object));
  }

  PtrComprCageBase cage_base(isolate_);
  Tagged<HeapObject> heap_obj = Cast<HeapObject>(*object);
  InstanceType instance_type = heap_obj->map(cage_base)->instance_type();

  // Oddball checks (true/false) — not instance type matches.
  if (IsTrue(*object, isolate_)) {
    AppendCStringLiteral("true");
    return true;
  }
  if (IsFalse(*object, isolate_)) {
    AppendCStringLiteral("false");
    return true;
  }

  // Switch-based dispatch — JSON-common types first for branch prediction.
  switch (instance_type) {
    case HEAP_NUMBER_TYPE:
      return SerializeHeapNumber(Cast<HeapNumber>(object));
    case JS_ARRAY_TYPE:
      return SerializeJSArray(Cast<JSArray>(object));
    case JS_DATE_TYPE:
      return SerializeJSDate(Cast<JSDate>(object));
    case JS_MAP_TYPE:
      return SerializeJSMap(Cast<JSMap>(object));
    case JS_SET_TYPE:
      return SerializeJSSet(Cast<JSSet>(object));
    case BIGINT_TYPE:
      return SerializeBigInt(Cast<BigInt>(object));
    default:
      if (InstanceTypeChecker::IsString(instance_type)) {
        return SerializeStringValue(Cast<String>(object));
      }
      if (InstanceTypeChecker::IsJSRegExp(instance_type)) {
        return SerializeJSRegExp(Cast<JSRegExp>(object));
      }
      if (InstanceTypeChecker::IsJSTypedArray(instance_type)) {
        return SerializeJSTypedArray(Cast<JSTypedArray>(object));
      }
      if (IsJSObject(*object)) {
        Handle<JSObject> js_obj = Cast<JSObject>(object);
        // TimeOnly/Duration objects always have a DONT_ENUM property (__type__).
        // Normal JSON objects never do. Skip the expensive property lookups
        // unless we find a DONT_ENUM descriptor.
        bool may_be_time_type = false;
        {
          DisallowGarbageCollection no_gc;
          Tagged<Map> obj_map = js_obj->map();
          Tagged<DescriptorArray> desc = obj_map->instance_descriptors();
          for (InternalIndex idx : obj_map->IterateOwnDescriptors()) {
            if (desc->GetDetails(idx).IsDontEnum()) { may_be_time_type = true; break; }
          }
        }
        if (may_be_time_type) {
          if (IsTimeOnly(js_obj)) return SerializeTimeOnly(js_obj);
          if (IsDuration(js_obj)) return SerializeDuration(js_obj);
        }
        return SerializeJSObject(js_obj);
      }
      break;
  }

  AppendCStringLiteral("null");
  return true;
}

// ── String serialization with escape table + SIMD/SWAR/Scalar ──────

// Scalar: per-character escape, called from SWAR when an escape is found.
template <typename DestChar>
void RdnStringifier::SerializeStringUncheckedScalar(
    const uint8_t* chars, size_t length, size_t start,
    size_t uncopied_src_index, NoExtendBuilder<DestChar>* dest) {
  for (size_t i = start; i < length; i++) {
    uint8_t c = chars[i];
    if (V8_LIKELY(DoNotEscape(c))) continue;
    dest->AppendSubstring(chars, uncopied_src_index, i);
    DCHECK_LT(c, 0x60);
    dest->AppendCString(&RdnEscapeTable[c * kRdnEscapeTableEntrySize]);
    uncopied_src_index = i + 1;
  }
  dest->AppendSubstring(chars, uncopied_src_index, length);
}

// SWAR: scans 4 bytes at a time, falls through to scalar.
template <typename DestChar>
V8_CLANG_NO_SANITIZE("alignment")
void RdnStringifier::SerializeStringUncheckedSWAR(
    const uint8_t* chars, size_t length, size_t start,
    size_t uncopied_src_index, NoExtendBuilder<DestChar>* dest) {
  using PackedT = uint32_t;
  static constexpr size_t stride = sizeof(PackedT);
  size_t i = start;
  for (; i + (stride - 1) < length; i += stride) {
    PackedT packed = *reinterpret_cast<const PackedT*>(chars + i);
    if (V8_UNLIKELY(NeedsEscape(packed))) break;
  }
  SerializeStringUncheckedScalar(chars, length, i, uncopied_src_index, dest);
}

// SIMD: uses Highway to scan 16 bytes per iteration.
template <typename DestChar>
void RdnStringifier::SerializeStringUncheckedSIMD(
    const uint8_t* chars, size_t length,
    NoExtendBuilder<DestChar>* dest) {
  namespace hw = hwy::HWY_NAMESPACE;

  size_t uncopied_src_index = 0;
  const uint8_t* block = chars;
  const uint8_t* end = chars + length;
  hw::FixedTag<uint8_t, 16> tag;
  static const size_t stride = hw::Lanes(tag);

  const auto mask_0x20 = hw::Set(tag, 0x20);
  const auto mask_0x22 = hw::Set(tag, 0x22);
  const auto mask_0x5c = hw::Set(tag, 0x5c);

  for (; block + (stride - 1) < end; block += stride) {
    const auto input = hw::LoadU(tag, block);
    const auto has_lower_than_0x20 = hw::Lt(input, mask_0x20);
    const auto has_0x22 = hw::Eq(input, mask_0x22);
    const auto has_0x5c = hw::Eq(input, mask_0x5c);
    const auto result = hw::Or(hw::Or(has_lower_than_0x20, has_0x22), has_0x5c);

    if (V8_LIKELY(hw::AllFalse(tag, result))) continue;

    size_t index = hw::FindKnownFirstTrue(tag, result);
    uint8_t found_char = block[index];
    const size_t char_index = block - chars + index;
    dest->AppendSubstring(chars, uncopied_src_index, char_index);
    DCHECK_LT(found_char, 0x60);
    dest->AppendCString(&RdnEscapeTable[found_char * kRdnEscapeTableEntrySize]);
    uncopied_src_index = char_index + 1;
    block += index + 1;
    block -= stride;  // Will be re-added by loop increment
  }

  // Handle remaining characters via SWAR → Scalar.
  const size_t start_index = block - chars;
  SerializeStringUncheckedSWAR(chars, length, start_index, uncopied_src_index,
                               dest);
}

// Dispatch: one-byte uses SIMD → SWAR → Scalar; two-byte stays scalar.
template <typename SrcChar, typename DestChar>
void RdnStringifier::SerializeStringUnchecked(
    base::Vector<const SrcChar> src, NoExtendBuilder<DestChar>* dest) {
  DCHECK(sizeof(DestChar) >= sizeof(SrcChar));
  if constexpr (sizeof(SrcChar) == 1) {
    // One-byte fast path: SIMD → SWAR → Scalar
    constexpr size_t kUseSimdLengthThreshold = 32;
    const uint8_t* chars = reinterpret_cast<const uint8_t*>(src.data());
    size_t length = src.size();
    if (length >= kUseSimdLengthThreshold) {
      SerializeStringUncheckedSIMD(chars, length, dest);
    } else {
      SerializeStringUncheckedSWAR(chars, length, 0, 0, dest);
    }
  } else {
    // Two-byte: keep scalar with surrogate handling
    size_t uncopied_src_index = 0;
    for (size_t i = 0; i < src.size(); i++) {
      SrcChar c = src[i];
      if (DoNotEscape(c)) {
        continue;
      } else if (base::IsInRange(c, static_cast<SrcChar>(0xD800),
                                 static_cast<SrcChar>(0xDFFF))) {
        dest->AppendSubstring(src.data(), uncopied_src_index, i);
        if (c <= 0xDBFF && i + 1 < src.size()) {
          SrcChar next = src[i + 1];
          if (base::IsInRange(next, static_cast<SrcChar>(0xDC00),
                              static_cast<SrcChar>(0xDFFF))) {
            dest->Append(c);
            dest->Append(next);
            i++;
            uncopied_src_index = i + 1;
            continue;
          }
        }
        char buf[7];
        snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(c));
        dest->AppendCString(buf);
        uncopied_src_index = i + 1;
      } else {
        dest->AppendSubstring(src.data(), uncopied_src_index, i);
        DCHECK_LT(c, 0x60);
        dest->AppendCString(&RdnEscapeTable[c * kRdnEscapeTableEntrySize]);
        uncopied_src_index = i + 1;
      }
    }
    dest->AppendSubstring(src.data(), uncopied_src_index, src.size());
  }
}

template <typename SrcChar, typename DestChar>
void RdnStringifier::SerializeStringChecked(
    Tagged<String> string, const DisallowGarbageCollection& no_gc) {
  base::Vector<const SrcChar> vector = string->GetCharVector<SrcChar>(no_gc);
  if V8_LIKELY (EscapedLengthIfCurrentPartFits(vector.size())) {
    NoExtendBuilder<DestChar> no_extend(
        reinterpret_cast<DestChar*>(part_ptr_) + current_index_,
        &current_index_);
    SerializeStringUnchecked<SrcChar, DestChar>(vector, &no_extend);
  } else {
    // Slow path: append substring by substring with possible Extend.
    size_t uncopied_src_index = 0;
    for (size_t i = 0; i < vector.size(); i++) {
      SrcChar c = vector.at(i);
      if (DoNotEscape(c)) {
        continue;
      } else if (sizeof(SrcChar) != 1 &&
                 base::IsInRange(c, static_cast<SrcChar>(0xD800),
                                 static_cast<SrcChar>(0xDFFF))) {
        AppendSubstring(vector.data(), uncopied_src_index, i);
        if (c <= 0xDBFF && i + 1 < vector.size()) {
          SrcChar next = vector.at(i + 1);
          if (base::IsInRange(next, static_cast<SrcChar>(0xDC00),
                              static_cast<SrcChar>(0xDFFF))) {
            Append<SrcChar, DestChar>(c);
            Append<SrcChar, DestChar>(next);
            i++;
            uncopied_src_index = i + 1;
            continue;
          }
        }
        char buf[7];
        snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(c));
        AppendCString(buf);
        uncopied_src_index = i + 1;
      } else {
        AppendSubstring(vector.data(), uncopied_src_index, i);
        DCHECK_LT(c, 0x60);
        AppendCString(&RdnEscapeTable[c * kRdnEscapeTableEntrySize]);
        uncopied_src_index = i + 1;
      }
    }
    AppendSubstring(vector.data(), uncopied_src_index, vector.size());
  }
}

bool RdnStringifier::SerializeStringValue(Handle<String> string) {
  string = String::Flatten(isolate_, string);
  AppendCharacter('"');
  {
    DisallowGarbageCollection no_gc;
    Tagged<String> raw = *string;
    if (encoding_ == String::ONE_BYTE_ENCODING) {
      if (String::IsOneByteRepresentationUnderneath(raw)) {
        SerializeStringChecked<uint8_t, uint8_t>(raw, no_gc);
      } else {
        ChangeEncoding();
        if (String::IsOneByteRepresentationUnderneath(raw)) {
          SerializeStringChecked<uint8_t, base::uc16>(raw, no_gc);
        } else {
          SerializeStringChecked<base::uc16, base::uc16>(raw, no_gc);
        }
      }
    } else {
      if (String::IsOneByteRepresentationUnderneath(raw)) {
        SerializeStringChecked<uint8_t, base::uc16>(raw, no_gc);
      } else {
        SerializeStringChecked<base::uc16, base::uc16>(raw, no_gc);
      }
    }
  }
  AppendCharacter('"');
  return true;
}

// ── Number serialization ──────────────────────────────────────────

bool RdnStringifier::SerializeSmi(Tagged<Smi> smi) {
  static_assert(Smi::kMaxValue <= 2147483647);
  static_assert(Smi::kMinValue >= -2147483648);
  static constexpr uint32_t kBufferSize = sizeof("-2147483648") - 1;
  char chars[kBufferSize];
  base::Vector<char> buffer(chars, kBufferSize);
  AppendStringView(IntToStringView(smi.value(), buffer));
  return true;
}

bool RdnStringifier::SerializeDouble(double value) {
  if (std::isnan(value)) {
    AppendCStringLiteral("NaN");
    return true;
  }
  if (std::isinf(value)) {
    if (value > 0) {
      AppendCStringLiteral("Infinity");
    } else {
      AppendCStringLiteral("-Infinity");
    }
    return true;
  }
  static constexpr uint32_t kBufferSize = 100;
  char chars[kBufferSize];
  base::Vector<char> buffer(chars, kBufferSize);
  std::string_view str = DoubleToStringView(value, buffer);
  AppendStringView(str);
  return true;
}

bool RdnStringifier::SerializeHeapNumber(Handle<HeapNumber> number) {
  return SerializeDouble(number->value());
}

// ── BigInt serialization ──────────────────────────────────────────

bool RdnStringifier::SerializeBigInt(Handle<BigInt> bigint) {
  Handle<String> str = BigInt::ToString(isolate_, bigint).ToHandleChecked();
  AppendString(str);
  AppendCharacter('n');
  return true;
}

// ── Array serialization (ElementsKind-aware) ──────────────────────

bool RdnStringifier::SerializeJSArray(Handle<JSArray> array) {
  uint32_t length = 0;
  Object::ToArrayLength(array->length(), &length);

  if (length == 0) {
    AppendCStringLiteral("[]");
    return true;
  }

  Result stack_push = StackPush(array);
  if (stack_push != SUCCESS) return false;

  AppendCharacter('[');

  // Fast path: dispatch on ElementsKind.
  ElementsKind kind = array->GetElementsKind();

  switch (kind) {
    case PACKED_SMI_ELEMENTS: {
      DisallowGarbageCollection no_gc;
      Tagged<FixedArray> elements = Cast<FixedArray>(array->elements());
      for (uint32_t i = 0; i < length; i++) {
        if (i > 0) AppendCharacter(',');
        SerializeSmi(Cast<Smi>(elements->get(i)));
      }
      break;
    }
    case PACKED_DOUBLE_ELEMENTS: {
      DisallowGarbageCollection no_gc;
      Tagged<FixedDoubleArray> elements =
          Cast<FixedDoubleArray>(array->elements());
      for (uint32_t i = 0; i < length; i++) {
        if (i > 0) AppendCharacter(',');
        SerializeDouble(elements->get_scalar(i));
      }
      break;
    }
    case PACKED_ELEMENTS: {
      Tagged<FixedArray> elems = Cast<FixedArray>(array->elements());
      for (uint32_t i = 0; i < length; i++) {
        if (i > 0) AppendCharacter(',');
        Tagged<Object> element = elems->get(i);
        // Check Smi inline to avoid Handle allocation.
        if (IsSmi(element)) {
          SerializeSmi(Cast<Smi>(element));
          continue;
        }
        if (IsUndefined(element, isolate_) || IsJSFunction(element) ||
            IsSymbol(element)) {
          AppendCStringLiteral("null");
          continue;
        }
        Handle<Object> elem(element, isolate_);
        if (!SerializeValue(elem)) {
          StackPop();
          return false;
        }
        // Re-acquire elements pointer after potential GC from SerializeValue.
        elems = Cast<FixedArray>(array->elements());
      }
      break;
    }
    default: {
      // Slow path: use GetElement for holey/dictionary arrays.
      for (uint32_t i = 0; i < length; i++) {
        if (i > 0) AppendCharacter(',');
        Handle<Object> element;
        MaybeHandle<Object> maybe_element =
            JSReceiver::GetElement(isolate_, array, i);
        if (!maybe_element.ToHandle(&element)) {
          StackPop();
          return false;
        }
        if (IsUndefined(*element, isolate_) || IsJSFunction(*element) ||
            IsSymbol(*element)) {
          AppendCStringLiteral("null");
        } else {
          if (!SerializeValue(element)) {
            StackPop();
            return false;
          }
        }
      }
      break;
    }
  }

  AppendCharacter(']');
  StackPop();
  return true;
}

// ── Object serialization (fast path with descriptor iteration) ────

bool RdnStringifier::SerializeJSObject(Handle<JSObject> object) {
  PtrComprCageBase cage_base(isolate_);

  if (!CanFastSerializeJSObject(*object, isolate_)) {
    return SerializeJSObjectSlow(object);
  }

  DirectHandle<Map> map(object->map(cage_base), isolate_);
  if (map->NumberOfOwnDescriptors() == 0) {
    AppendCStringLiteral("{}");
    return true;
  }

  Result stack_push = StackPush(object);
  if (stack_push != SUCCESS) return false;

  AppendCharacter('{');
  bool comma = false;

  for (InternalIndex i : map->IterateOwnDescriptors()) {
    Handle<String> key_name;
    PropertyDetails details = PropertyDetails::Empty();
    bool is_fast_key = false;
    {
      DisallowGarbageCollection no_gc;
      Tagged<DescriptorArray> descriptors =
          map->instance_descriptors(cage_base);
      Tagged<Name> name = descriptors->GetKey(i);
      if (!IsString(name, cage_base)) continue;
      Tagged<String> key = Cast<String>(name);
      details = descriptors->GetDetails(i);

      // Check if key is a one-byte string needing no escaping.
      if (IsSeqOneByteString(key)) {
        Tagged<SeqOneByteString> seq = Cast<SeqOneByteString>(key);
        is_fast_key = DoNotEscapeString(seq->GetChars(no_gc), seq->length());
      }

      key_name = handle(key, isolate_);
    }
    if (details.IsDontEnum()) continue;

    Handle<JSAny> property;
    if (details.location() == PropertyLocation::kField &&
        *map == object->map(cage_base)) {
      DCHECK_EQ(PropertyKind::kData, details.kind());
      FieldIndex field_index = FieldIndex::ForDetails(*map, details);
      property = handle(object->RawFastPropertyAt(field_index), isolate_);
    } else {
      // GetPropertyOrElement may trigger GC — can't use fast key path.
      is_fast_key = false;
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate_, property,
          Cast<JSAny>(Object::GetPropertyOrElement(isolate_, object, key_name)),
          false);
    }

    // Skip undefined, functions, symbols.
    if (IsUndefined(*property, isolate_) || IsJSFunction(*property) ||
        IsSymbol(*property)) {
      continue;
    }

    // ── Serialize key + separator ──
    if (comma) AppendCharacter(',');

    bool wrote_key_fast = false;
    {
      DisallowGarbageCollection no_gc;
      // Fast path 1: key is in the cache (internalized one-byte, no escaping).
      // This is the fastest path for repeated same-shape objects.
      wrote_key_fast = encoding_ == String::ONE_BYTE_ENCODING
          ? TrySerializeSimplePropertyKey<uint8_t>(*key_name, no_gc)
          : TrySerializeSimplePropertyKey<base::uc16>(*key_name, no_gc);
      if (!wrote_key_fast && is_fast_key && encoding_ == String::ONE_BYTE_ENCODING) {
        // Fast path 2: SeqOneByteString needing no escaping (not yet cached).
        Tagged<SeqOneByteString> seq = Cast<SeqOneByteString>(*key_name);
        const uint8_t* chars = seq->GetChars(no_gc);
        size_t len = seq->length();
        size_t total = len + 3;  // " + key + " + :
        if (CurrentPartCanFit(total + 1)) {
          uint8_t* dest = one_byte_ptr_ + current_index_;
          *dest++ = '"';
          memcpy(dest, chars, len);
          dest += len;
          *dest++ = '"';
          *dest++ = ':';
          current_index_ += total;
          if V8_UNLIKELY (current_index_ == part_length_) Extend();
          wrote_key_fast = true;
          key_cache_.TryInsert(*key_name);
        }
      }
    }
    if (!wrote_key_fast) {
      SerializeStringValue(key_name);
      AppendCharacter(':');
      key_cache_.TryInsert(*key_name);
    }
    comma = true;

    if (!SerializeValue(property)) {
      StackPop();
      return false;
    }
  }

  AppendCharacter('}');
  StackPop();
  return true;
}

bool RdnStringifier::SerializeJSObjectSlow(Handle<JSObject> object) {
  Handle<FixedArray> keys =
      KeyAccumulator::GetKeys(isolate_, object, KeyCollectionMode::kOwnOnly,
                              ENUMERABLE_STRINGS,
                              GetKeysConversion::kConvertToString)
          .ToHandleChecked();

  int length = keys->length();
  if (length == 0) {
    AppendCStringLiteral("{}");
    return true;
  }

  Result stack_push = StackPush(object);
  if (stack_push != SUCCESS) return false;

  AppendCharacter('{');
  bool first = true;
  for (int i = 0; i < length; i++) {
    Handle<String> key(Cast<String>(keys->get(i)), isolate_);
    Handle<Object> value;
    MaybeHandle<Object> maybe_value =
        Object::GetPropertyOrElement(isolate_, object, key);
    if (!maybe_value.ToHandle(&value)) {
      StackPop();
      return false;
    }

    if (IsUndefined(*value, isolate_) || IsJSFunction(*value) ||
        IsSymbol(*value)) {
      continue;
    }

    if (!first) AppendCharacter(',');
    first = false;
    SerializeStringValue(key);
    AppendCharacter(':');
    if (!SerializeValue(value)) {
      StackPop();
      return false;
    }
  }
  AppendCharacter('}');
  StackPop();
  return true;
}

// ── Date serialization (direct C++ formatting) ─────────────────────

bool RdnStringifier::SerializeJSDate(Handle<JSDate> date) {
  double value = date->value();
  if (std::isnan(value)) {
    AppendCStringLiteral("null");
    return true;
  }

  // Direct C++ date formatting — avoid calling toISOString() via JS.
  // Extract UTC date components from the millisecond timestamp.
  int64_t time_ms = static_cast<int64_t>(value);

  static constexpr int kMsPerSecond = 1000;
  static constexpr int kMsPerMinute = 60 * kMsPerSecond;
  static constexpr int kMsPerHour = 60 * kMsPerMinute;
  static constexpr int64_t kMsPerDay = 24 * kMsPerHour;

  // Days since epoch (floor division for negative values).
  int64_t days64;
  if (time_ms >= 0) {
    days64 = time_ms / kMsPerDay;
  } else {
    days64 = (time_ms - (kMsPerDay - 1)) / kMsPerDay;
  }
  int time_in_day_ms = static_cast<int>(time_ms - days64 * kMsPerDay);
  int days = static_cast<int>(days64);

  int ms = time_in_day_ms % kMsPerSecond;
  int sec = (time_in_day_ms / kMsPerSecond) % 60;
  int min = (time_in_day_ms / kMsPerMinute) % 60;
  int hour = (time_in_day_ms / kMsPerHour) % 24;

  // Civil date from days since epoch.
  // Algorithm from https://howardhinnant.github.io/date_algorithms.html
  int z = days + 719468;
  int era = (z >= 0 ? z : z - 146096) / 146097;
  unsigned doe = static_cast<unsigned>(z - era * 146097);
  unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  int y = static_cast<int>(yoe) + era * 400;
  unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  unsigned mp = (5 * doy + 2) / 153;
  unsigned d = doy - (153 * mp + 2) / 5 + 1;
  unsigned m = mp < 10 ? mp + 3 : mp - 9;
  if (m <= 2) y++;

  int year = y;
  int month = static_cast<int>(m);
  int day = static_cast<int>(d);

  AppendCharacter('@');

  // Format: YYYY-MM-DDTHH:mm:ss.sssZ (always include milliseconds
  // to match JS Date.toISOString() and ensure roundtrip fidelity).
  char buf[32];
  snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
           year, month, day, hour, min, sec, ms);
  AppendCString(buf);
  return true;
}

// ── RegExp serialization ──────────────────────────────────────────

bool RdnStringifier::SerializeJSRegExp(Handle<JSRegExp> regexp) {
  AppendCharacter('/');
  Handle<String> source(regexp->source(), isolate_);
  AppendString(source);
  AppendCharacter('/');

  JSRegExp::Flags flags = regexp->flags();
  if (flags & JSRegExp::kHasIndices) AppendCharacter('d');
  if (flags & JSRegExp::kGlobal) AppendCharacter('g');
  if (flags & JSRegExp::kIgnoreCase) AppendCharacter('i');
  if (flags & JSRegExp::kMultiline) AppendCharacter('m');
  if (flags & JSRegExp::kDotAll) AppendCharacter('s');
  if (flags & JSRegExp::kUnicode) AppendCharacter('u');
  if (flags & JSRegExp::kUnicodeSets) AppendCharacter('v');
  if (flags & JSRegExp::kSticky) AppendCharacter('y');

  return true;
}

// ── Map serialization ─────────────────────────────────────────────

bool RdnStringifier::SerializeJSMap(Handle<JSMap> map) {
  Tagged<OrderedHashMap> table = Cast<OrderedHashMap>(map->table());
  int num_elements = table->NumberOfElements();

  if (num_elements == 0) {
    AppendCStringLiteral("Map{}");
    return true;
  }

  Result stack_push = StackPush(map);
  if (stack_push != SUCCESS) return false;

  AppendCharacter('{');
  bool first = true;
  ReadOnlyRoots roots(isolate_);

  for (InternalIndex i : table->IterateEntries()) {
    Tagged<Object> raw_key;
    if (!table->ToKey(roots, i, &raw_key)) continue;

    if (!first) AppendCharacter(',');
    first = false;

    Handle<Object> key(raw_key, isolate_);
    Handle<Object> value(table->ValueAt(i), isolate_);

    if (!SerializeValue(key)) { StackPop(); return false; }
    AppendCStringLiteral("=>");
    if (!SerializeValue(value)) { StackPop(); return false; }

    // Re-acquire table pointer after potential GC.
    table = Cast<OrderedHashMap>(map->table());
  }
  AppendCharacter('}');
  StackPop();
  return true;
}

// ── Set serialization ─────────────────────────────────────────────

bool RdnStringifier::SerializeJSSet(Handle<JSSet> set) {
  Tagged<OrderedHashSet> table = Cast<OrderedHashSet>(set->table());
  int num_elements = table->NumberOfElements();

  if (num_elements == 0) {
    AppendCStringLiteral("Set{}");
    return true;
  }

  Result stack_push = StackPush(set);
  if (stack_push != SUCCESS) return false;

  AppendCharacter('{');
  bool first = true;
  ReadOnlyRoots roots(isolate_);

  for (InternalIndex i : table->IterateEntries()) {
    Tagged<Object> raw_key;
    if (!table->ToKey(roots, i, &raw_key)) continue;

    if (!first) AppendCharacter(',');
    first = false;

    Handle<Object> value(raw_key, isolate_);
    if (!SerializeValue(value)) { StackPop(); return false; }

    // Re-acquire table pointer after potential GC.
    table = Cast<OrderedHashSet>(set->table());
  }
  AppendCharacter('}');
  StackPop();
  return true;
}

// ── TypedArray (Uint8Array) serialization ──────────────────────────

bool RdnStringifier::SerializeJSTypedArray(Handle<JSTypedArray> array) {
  size_t byte_length = array->byte_length();
  const uint8_t* data = static_cast<const uint8_t*>(array->DataPtr());

  AppendCStringLiteral("b\"");

  size_t i = 0;
  while (i + 2 < byte_length) {
    uint32_t triplet = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
    AppendCharacter(kBase64Table[(triplet >> 18) & 0x3F]);
    AppendCharacter(kBase64Table[(triplet >> 12) & 0x3F]);
    AppendCharacter(kBase64Table[(triplet >> 6) & 0x3F]);
    AppendCharacter(kBase64Table[triplet & 0x3F]);
    i += 3;
  }

  if (i + 1 == byte_length) {
    uint32_t val = data[i] << 16;
    AppendCharacter(kBase64Table[(val >> 18) & 0x3F]);
    AppendCharacter(kBase64Table[(val >> 12) & 0x3F]);
    AppendCharacter('=');
    AppendCharacter('=');
  } else if (i + 2 == byte_length) {
    uint32_t val = (data[i] << 16) | (data[i + 1] << 8);
    AppendCharacter(kBase64Table[(val >> 18) & 0x3F]);
    AppendCharacter(kBase64Table[(val >> 12) & 0x3F]);
    AppendCharacter(kBase64Table[(val >> 6) & 0x3F]);
    AppendCharacter('=');
  }

  AppendCharacter('"');
  return true;
}

// ── TimeOnly detection and serialization ──────────────────────────

bool RdnStringifier::IsTimeOnly(Handle<JSObject> object) {
  EnsureTimeTypeStringsInitialized();
  Handle<Object> type_val;
  MaybeHandle<Object> maybe_type =
      Object::GetProperty(isolate_, object, type_key_);
  if (!maybe_type.ToHandle(&type_val) || !IsString(*type_val)) return false;
  return String::Equals(isolate_, Cast<String>(type_val), time_only_str_);
}

bool RdnStringifier::SerializeTimeOnly(Handle<JSObject> object) {
  Handle<Object> h_val, m_val, s_val, ms_val;
  USE(Object::GetProperty(isolate_, object, hours_key_).ToHandle(&h_val));
  USE(Object::GetProperty(isolate_, object, minutes_key_).ToHandle(&m_val));
  USE(Object::GetProperty(isolate_, object, seconds_key_).ToHandle(&s_val));
  USE(Object::GetProperty(isolate_, object, ms_key_).ToHandle(&ms_val));

  int h = IsSmi(*h_val) ? Smi::ToInt(*h_val) : 0;
  int m = IsSmi(*m_val) ? Smi::ToInt(*m_val) : 0;
  int s = IsSmi(*s_val) ? Smi::ToInt(*s_val) : 0;
  int ms = IsSmi(*ms_val) ? Smi::ToInt(*ms_val) : 0;

  char buf[16];
  snprintf(buf, sizeof(buf), "@%02d:%02d:%02d", h, m, s);
  AppendCString(buf);

  if (ms > 0) {
    char ms_buf[8];
    snprintf(ms_buf, sizeof(ms_buf), ".%03d", ms);
    AppendCString(ms_buf);
  }

  return true;
}

// ── Duration detection and serialization ──────────────────────────

bool RdnStringifier::IsDuration(Handle<JSObject> object) {
  EnsureTimeTypeStringsInitialized();
  Handle<Object> type_val;
  MaybeHandle<Object> maybe_type =
      Object::GetProperty(isolate_, object, type_key_);
  if (!maybe_type.ToHandle(&type_val) || !IsString(*type_val)) return false;
  return String::Equals(isolate_, Cast<String>(type_val), duration_str_);
}

bool RdnStringifier::SerializeDuration(Handle<JSObject> object) {
  Handle<Object> iso_val;
  USE(Object::GetProperty(isolate_, object, iso_key_).ToHandle(&iso_val));

  AppendCharacter('@');
  if (IsString(*iso_val)) {
    AppendString(Cast<String>(iso_val));
  }
  return true;
}

}  // namespace

// ── Public entry point ────────────────────────────────────────────

MaybeHandle<Object> RdnStringify(Isolate* isolate, Handle<Object> object) {
  RdnStringifier stringifier(isolate);
  return stringifier.Stringify(object);
}

}  // namespace internal
}  // namespace v8
