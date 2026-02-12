// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// RDN stringifier — converts V8 values to RDN text format.
// Ported from json-stringifier.cc with direct buffer management,
// escape lookup tables, SWAR NeedsEscape, ElementsKind-aware array
// serialization, fast object serialization, and circular reference detection.

#include "src/json/rdn-stringifier.h"

#include <cinttypes>
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
#include "src/objects/field-index-inl.h"
#include "src/execution/protectors-inl.h"
#include "src/strings/string-builder-inl.h"
#include "src/base/small-vector.h"
#include "src/objects/oddball-inl.h"
#include "src/zone/zone.h"
#include "src/zone/zone-list-inl.h"

#include "hwy/highway.h"

namespace v8 {
namespace internal {

namespace {

// ── Base64 encoding table ──────────────────────────────────────────

static const char kBase64Table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// ── Digit-pair table for fast numeric formatting ────────────────────
// Pre-computed pairs "00", "01", ..., "99" for direct 2-char writes.
// Used by date/time formatting to avoid snprintf overhead.
static constexpr char kDigitPairs[200] = {
    '0', '0', '0', '1', '0', '2', '0', '3', '0', '4', '0', '5', '0', '6',
    '0', '7', '0', '8', '0', '9', '1', '0', '1', '1', '1', '2', '1', '3',
    '1', '4', '1', '5', '1', '6', '1', '7', '1', '8', '1', '9', '2', '0',
    '2', '1', '2', '2', '2', '3', '2', '4', '2', '5', '2', '6', '2', '7',
    '2', '8', '2', '9', '3', '0', '3', '1', '3', '2', '3', '3', '3', '4',
    '3', '5', '3', '6', '3', '7', '3', '8', '3', '9', '4', '0', '4', '1',
    '4', '2', '4', '3', '4', '4', '4', '5', '4', '6', '4', '7', '4', '8',
    '4', '9', '5', '0', '5', '1', '5', '2', '5', '3', '5', '4', '5', '5',
    '5', '6', '5', '7', '5', '8', '5', '9', '6', '0', '6', '1', '6', '2',
    '6', '3', '6', '4', '6', '5', '6', '6', '6', '7', '6', '8', '6', '9',
    '7', '0', '7', '1', '7', '2', '7', '3', '7', '4', '7', '5', '7', '6',
    '7', '7', '7', '8', '7', '9', '8', '0', '8', '1', '8', '2', '8', '3',
    '8', '4', '8', '5', '8', '6', '8', '7', '8', '8', '8', '9', '9', '0',
    '9', '1', '9', '2', '9', '3', '9', '4', '9', '5', '9', '6', '9', '7',
    '9', '8', '9', '9',
};

// Write a 2-digit zero-padded number to buf using the digit-pair table.
V8_INLINE void WriteDigitPair(char* buf, int value) {
  DCHECK_GE(value, 0);
  DCHECK_LT(value, 100);
  memcpy(buf, &kDigitPairs[value * 2], 2);
}

// Write a 4-digit zero-padded year to buf.
V8_INLINE void WriteYear(char* buf, int year) {
  DCHECK_GE(year, 0);
  DCHECK_LT(year, 10000);
  WriteDigitPair(buf, year / 100);
  WriteDigitPair(buf + 2, year % 100);
}

// Write a 3-digit zero-padded millisecond to buf.
V8_INLINE void WriteMillis(char* buf, int ms) {
  DCHECK_GE(ms, 0);
  DCHECK_LT(ms, 1000);
  buf[0] = '0' + ms / 100;
  WriteDigitPair(buf + 1, ms % 100);
}

// Format a date-time as "@YYYY-MM-DDTHH:mm:ss.sssZ" (exactly 25 chars)
// directly into buf using digit-pair lookups. No snprintf overhead.
V8_INLINE void FormatDateDirect(char* buf, int year, int month, int day,
                                int hour, int min, int sec, int ms) {
  buf[0] = '@';
  WriteYear(buf + 1, year);
  buf[5] = '-';
  WriteDigitPair(buf + 6, month);
  buf[8] = '-';
  WriteDigitPair(buf + 9, day);
  buf[11] = 'T';
  WriteDigitPair(buf + 12, hour);
  buf[14] = ':';
  WriteDigitPair(buf + 15, min);
  buf[17] = ':';
  WriteDigitPair(buf + 18, sec);
  buf[20] = '.';
  WriteMillis(buf + 21, ms);
  buf[24] = 'Z';
}

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

  // Cached maps for O(1) TimeOnly/Duration detection.
  // After first successful detection, we cache the map so subsequent
  // checks are a simple pointer comparison instead of property lookups.
  Handle<Map> cached_time_only_map_;
  Handle<Map> cached_duration_map_;

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
    case HOLEY_SMI_ELEMENTS: {
      // Fast path for holey Smi arrays when no-elements protector is intact.
      if (!Protectors::IsNoElementsIntact(isolate_)) goto slow_path;
      DisallowGarbageCollection no_gc;
      Tagged<FixedArray> elements = Cast<FixedArray>(array->elements());
      for (uint32_t i = 0; i < length; i++) {
        if (i > 0) AppendCharacter(',');
        Tagged<Object> element = elements->get(i);
        if (IsTheHole(element, isolate_)) {
          AppendCStringLiteral("null");
        } else {
          SerializeSmi(Cast<Smi>(element));
        }
      }
      break;
    }
    case HOLEY_DOUBLE_ELEMENTS: {
      if (!Protectors::IsNoElementsIntact(isolate_)) goto slow_path;
      DisallowGarbageCollection no_gc;
      Tagged<FixedDoubleArray> elements =
          Cast<FixedDoubleArray>(array->elements());
      for (uint32_t i = 0; i < length; i++) {
        if (i > 0) AppendCharacter(',');
        if (elements->is_the_hole(i)) {
          AppendCStringLiteral("null");
        } else {
          SerializeDouble(elements->get_scalar(i));
        }
      }
      break;
    }
    case HOLEY_ELEMENTS: {
      if (!Protectors::IsNoElementsIntact(isolate_)) goto slow_path;
      Tagged<FixedArray> elems = Cast<FixedArray>(array->elements());
      for (uint32_t i = 0; i < length; i++) {
        if (i > 0) AppendCharacter(',');
        Tagged<Object> element = elems->get(i);
        if (IsTheHole(element, isolate_)) {
          AppendCStringLiteral("null");
          continue;
        }
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
        elems = Cast<FixedArray>(array->elements());
      }
      break;
    }
    default: {
    slow_path:
      // Slow path: use GetElement for dictionary arrays or when
      // no-elements protector is not intact.
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

  // Format: @YYYY-MM-DDTHH:mm:ss.sssZ (always include milliseconds
  // to match JS Date.toISOString() and ensure roundtrip fidelity).
  // Direct digit-pair writing: ~10ns vs ~100-200ns for snprintf.
  char buf[25];
  FormatDateDirect(buf, year, month, day, hour, min, sec, ms);
  for (int i = 0; i < 25; i++) AppendCharacter(buf[i]);
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

    Tagged<Object> raw_value = table->ValueAt(i);

    // Inline Smi fast path: serialize Smi keys/values directly without
    // Handle allocation or SerializeValue dispatch overhead.
    if (IsSmi(raw_key) && IsSmi(raw_value)) {
      SerializeSmi(Cast<Smi>(raw_key));
      AppendCStringLiteral("=>");
      SerializeSmi(Cast<Smi>(raw_value));
      continue;
    }

    Handle<Object> key(raw_key, isolate_);
    Handle<Object> value(raw_value, isolate_);

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

  // Pre-compute output size and ensure buffer capacity once.
  // base64 output: 4 chars per 3 bytes, rounded up, + b"..." wrapper = 3 chars.
  size_t b64_len = (byte_length + 2) / 3 * 4;
  size_t total_len = b64_len + 3;  // b" + encoded + "

  // Ensure buffer has space for the entire output.
  while (!CurrentPartCanFit(total_len + 1)) {
    Extend();
    if (V8_UNLIKELY(overflowed_)) return false;
  }

  AppendCStringLiteral("b\"");

  // Batched writes: encode 3 bytes → 4 chars directly via lookup table.
  // Buffer capacity is already ensured, so individual AppendCharacter
  // branch checks are the only overhead remaining.
  size_t i = 0;
  while (i + 2 < byte_length) {
    uint32_t triplet = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
    AppendCharacter(kBase64Table[(triplet >> 18) & 0x3F]);
    AppendCharacter(kBase64Table[(triplet >> 12) & 0x3F]);
    AppendCharacter(kBase64Table[(triplet >> 6) & 0x3F]);
    AppendCharacter(kBase64Table[triplet & 0x3F]);
    i += 3;
  }

  // Handle remaining 1 or 2 bytes.
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
  // Fast path: O(1) map identity check if we've cached the TimeOnly map.
  if (!cached_time_only_map_.is_null() &&
      object->map() == *cached_time_only_map_) {
    return true;
  }
  // Slow path: property-based detection (first encounter).
  Handle<Object> type_val;
  MaybeHandle<Object> maybe_type =
      Object::GetProperty(isolate_, object, type_key_);
  if (!maybe_type.ToHandle(&type_val) || !IsString(*type_val)) return false;
  if (!String::Equals(isolate_, Cast<String>(type_val), time_only_str_)) {
    return false;
  }
  // Cache the map for subsequent O(1) detection.
  if (cached_time_only_map_.is_null()) {
    cached_time_only_map_ = handle(object->map(), isolate_);
  }
  return true;
}

bool RdnStringifier::SerializeTimeOnly(Handle<JSObject> object) {
  int h, m, s, ms;

  // Fast path: if map is cached, read Smi fields at known offsets via
  // direct field access — no property lookups needed.
  if (!cached_time_only_map_.is_null() &&
      object->map() == *cached_time_only_map_ &&
      object->HasFastProperties()) {
    Tagged<Map> map = object->map();
    // Fields: hours(0), minutes(1), seconds(2), milliseconds(3).
    Tagged<Object> h_raw = object->RawFastPropertyAt(
        FieldIndex::ForPropertyIndex(map, 0, Representation::Tagged()));
    Tagged<Object> m_raw = object->RawFastPropertyAt(
        FieldIndex::ForPropertyIndex(map, 1, Representation::Tagged()));
    Tagged<Object> s_raw = object->RawFastPropertyAt(
        FieldIndex::ForPropertyIndex(map, 2, Representation::Tagged()));
    Tagged<Object> ms_raw = object->RawFastPropertyAt(
        FieldIndex::ForPropertyIndex(map, 3, Representation::Tagged()));
    h = IsSmi(h_raw) ? Smi::ToInt(h_raw) : 0;
    m = IsSmi(m_raw) ? Smi::ToInt(m_raw) : 0;
    s = IsSmi(s_raw) ? Smi::ToInt(s_raw) : 0;
    ms = IsSmi(ms_raw) ? Smi::ToInt(ms_raw) : 0;
  } else {
    // Fallback: property-based access.
    Handle<Object> h_val, m_val, s_val, ms_val;
    USE(Object::GetProperty(isolate_, object, hours_key_).ToHandle(&h_val));
    USE(Object::GetProperty(isolate_, object, minutes_key_).ToHandle(&m_val));
    USE(Object::GetProperty(isolate_, object, seconds_key_).ToHandle(&s_val));
    USE(Object::GetProperty(isolate_, object, ms_key_).ToHandle(&ms_val));
    h = IsSmi(*h_val) ? Smi::ToInt(*h_val) : 0;
    m = IsSmi(*m_val) ? Smi::ToInt(*m_val) : 0;
    s = IsSmi(*s_val) ? Smi::ToInt(*s_val) : 0;
    ms = IsSmi(*ms_val) ? Smi::ToInt(*ms_val) : 0;
  }

  // Direct digit-pair writing for time: @HH:MM:SS[.mmm]
  char buf[13];  // max: @HH:MM:SS.mmm = 13 chars
  buf[0] = '@';
  WriteDigitPair(buf + 1, h);
  buf[3] = ':';
  WriteDigitPair(buf + 4, m);
  buf[6] = ':';
  WriteDigitPair(buf + 7, s);
  int len = 9;
  if (ms > 0) {
    buf[9] = '.';
    WriteMillis(buf + 10, ms);
    len = 13;
  }
  for (int i = 0; i < len; i++) AppendCharacter(buf[i]);

  return true;
}

// ── Duration detection and serialization ──────────────────────────

bool RdnStringifier::IsDuration(Handle<JSObject> object) {
  EnsureTimeTypeStringsInitialized();
  // Fast path: O(1) map identity check.
  if (!cached_duration_map_.is_null() &&
      object->map() == *cached_duration_map_) {
    return true;
  }
  // Slow path: property-based detection.
  Handle<Object> type_val;
  MaybeHandle<Object> maybe_type =
      Object::GetProperty(isolate_, object, type_key_);
  if (!maybe_type.ToHandle(&type_val) || !IsString(*type_val)) return false;
  if (!String::Equals(isolate_, Cast<String>(type_val), duration_str_)) {
    return false;
  }
  // Cache the map for subsequent O(1) detection.
  if (cached_duration_map_.is_null()) {
    cached_duration_map_ = handle(object->map(), isolate_);
  }
  return true;
}

bool RdnStringifier::SerializeDuration(Handle<JSObject> object) {
  // Fast path: direct field access when map is cached.
  if (!cached_duration_map_.is_null() &&
      object->map() == *cached_duration_map_ &&
      object->HasFastProperties()) {
    Tagged<Map> map = object->map();
    // Fields: iso(0).
    Tagged<Object> iso_raw = object->RawFastPropertyAt(
        FieldIndex::ForPropertyIndex(map, 0, Representation::Tagged()));
    AppendCharacter('@');
    if (IsString(iso_raw)) {
      AppendString(handle(Cast<String>(iso_raw), isolate_));
    }
    return true;
  }

  // Fallback: property-based access.
  Handle<Object> iso_val;
  USE(Object::GetProperty(isolate_, object, iso_key_).ToHandle(&iso_val));

  AppendCharacter('@');
  if (IsString(*iso_val)) {
    AppendString(Cast<String>(iso_val));
  }
  return true;
}

// ═══════════════════════════════════════════════════════════════════
// Fast-path RDN Stringifier (GC-free, continuation-based)
// Modeled on FastJsonStringifier from json-stringifier.cc.
// Runs GC-free for JSON-compatible types + Date.
// Falls back to RdnStringifier for RDN-only types.
// ═══════════════════════════════════════════════════════════════════

static constexpr char kRdnStringifierZoneName[] = "rdn-stringifier-zone";

template <typename Char>
class RdnOutBuffer {
 public:
  explicit RdnOutBuffer(AccountingAllocator* allocator) : allocator_(allocator) {
    cur_ = stack_buffer_;
    segment_end_ = cur_ + kStackBufferSize;
  }
  template <typename SrcChar>
    requires(sizeof(Char) >= sizeof(SrcChar))
  V8_INLINE void AppendCharacter(SrcChar c) {
    ReduceCurrentCapacity(1);
    DCHECK_GE(SegmentFreeChars(), 1);
    *cur_++ = c;
  }
  template <typename SrcChar>
    requires(sizeof(Char) >= sizeof(SrcChar))
  void Append(const SrcChar* chars, size_t length) {
    ReduceCurrentCapacity(length);
    DCHECK_GE(SegmentFreeChars(), length);
    CopyChars(cur_, chars, length);
    cur_ += length;
  }
  void EnsureCapacity(size_t size) {
#ifdef DEBUG
    current_requested_capacity_ = size;
#endif
    if (V8_LIKELY(size <= SegmentFreeChars())) return;
    Extend(size);
    DCHECK_GE(CurSegmentCapacity(), size);
  }
  size_t length() const {
    if (ZoneUsed()) {
      DCHECK_GT(segments_->length(), 0);
      size_t len = stack_buffer_size_;
      for (int i = 0; i < segments_->length() - 1; i++) {
        len += segments_->at(i).size();
      }
      len += CurSegmentLength();
      return len;
    } else {
      return StackBufferLength();
    }
  }
  template <typename Dst>
  void CopyTo(Dst* dst) {
    if (ZoneUsed()) {
      CopyChars(dst, stack_buffer_, stack_buffer_size_);
      dst += stack_buffer_size_;
      DCHECK_GT(segments_->length(), 0);
      for (int i = 0; i < segments_->length() - 1; i++) {
        base::Vector<Char> seg = segments_.value()[i];
        CopyChars(dst, seg.begin(), seg.size());
        dst += seg.size();
      }
      base::Vector<Char> seg = segments_->last();
      CopyChars(dst, seg.begin(), CurSegmentLength());
    } else {
      CopyChars(dst, stack_buffer_, StackBufferLength());
    }
  }

 private:
  static constexpr uint32_t kInitialSegmentSize = 2 * KB;
  static constexpr uint32_t kMaxSegmentSize = 32 * KB;
  static_assert(base::bits::IsPowerOfTwo(kInitialSegmentSize));
  static_assert(base::bits::IsPowerOfTwo(kMaxSegmentSize));
  static constexpr uint8_t kInitialSegmentSizeHighestBit =
      kBitsPerInt - base::bits::CountLeadingZeros32(kInitialSegmentSize) - 1;
  static constexpr uint8_t kMaxSegmentSizeHighestBit =
      kBitsPerInt - base::bits::CountLeadingZeros32(kMaxSegmentSize) - 1;
  static constexpr size_t kStackBufferSize = 256;

  V8_NOINLINE V8_PRESERVE_MOST void Extend(size_t min_size) {
    if (ZoneUsed()) {
      segments_->last().Truncate(CurSegmentLength());
    } else {
      stack_buffer_size_ = StackBufferLength();
      zone_.emplace(allocator_, kRdnStringifierZoneName);
      segments_.emplace(1, &zone_.value());
    }
    const size_t new_segment_size =
        std::max(min_size, SegmentCapacity(segments_->length()));
    segments_->Add(zone_->AllocateVector<Char>(new_segment_size),
                   &zone_.value());
    cur_ = segments_->last().begin();
    segment_end_ = segments_->last().end();
  }
  V8_INLINE size_t SegmentFreeChars() const { return segment_end_ - cur_; }
  V8_INLINE size_t StackBufferLength() const {
    DCHECK(!ZoneUsed());
    return cur_ - stack_buffer_;
  }
  V8_INLINE size_t CurSegmentLength() const {
    DCHECK(ZoneUsed());
    return cur_ - segments_->last().begin();
  }
  V8_INLINE size_t SegmentCapacity(size_t segment) {
    return 1u << std::min<size_t>(segment + kInitialSegmentSizeHighestBit,
                                  kMaxSegmentSizeHighestBit);
  }
  V8_INLINE size_t CurSegmentCapacity() {
    DCHECK(ZoneUsed());
    DCHECK_GT(segments_->length(), 0);
    return segments_->last().size();
  }
  V8_INLINE void ReduceCurrentCapacity(size_t size) {
#ifdef DEBUG
    DCHECK_LE(size, current_requested_capacity_);
    current_requested_capacity_ -= size;
#endif
  }
  V8_INLINE bool ZoneUsed() const { return zone_.has_value(); }

  AccountingAllocator* allocator_;
  Char stack_buffer_[kStackBufferSize];
  size_t stack_buffer_size_;
  Char* cur_;
  Char* segment_end_;
  std::optional<Zone> zone_;
  std::optional<ZoneList<base::Vector<Char>>> segments_;
#ifdef DEBUG
  size_t current_requested_capacity_;
#endif
};

enum FastRdnStringifierResult {
  SUCCESS, JS_OBJECT, JS_ARRAY, UNDEFINED, CHANGE_ENCODING, SLOW_PATH,
  EXCEPTION
};

enum class FastRdnStringifierObjectKeyResult : uint8_t {
  kSuccess, kChangeEncoding, kSlow
};

class RdnContinuationRecord {
 public:
  enum Type {
    kObject, kArray,
    kObjectResume_FastIterable, kObjectResume_SlowIterable,
    kObjectResume_Uninitialized,
    kArrayResume, kArrayResume_Holey,
    kArrayResume_WithInterrupts, kArrayResume_Holey_WithInterrupts,
    kSimpleObject, kObjectKey
  };
  using ObjectT = UnionOf<JSAny, FixedArrayBase>;

  static constexpr RdnContinuationRecord ForSimpleObject(Tagged<JSAny> obj) {
    return RdnContinuationRecord(Type::kSimpleObject, obj, 0, 0);
  }
  static constexpr RdnContinuationRecord ForJSAny(
      Tagged<JSAny> obj, FastRdnStringifierResult result) {
    return RdnContinuationRecord(ContinuationTypeFromResult(result), obj, 0, 0);
  }
  static constexpr RdnContinuationRecord ForJSArray(Tagged<JSAny> obj) {
    DCHECK(Is<JSArray>(obj));
    return RdnContinuationRecord(Type::kArray, obj, 0, 0);
  }
  template <ElementsKind kind, bool with_interrupt_check>
  static constexpr RdnContinuationRecord ForJSArrayResume(
      Tagged<FixedArrayBase> obj, uint32_t index, uint32_t length) {
    return RdnContinuationRecord(
        ContinuationTypeForArray(kind, with_interrupt_check), obj, index,
        length);
  }
  static constexpr RdnContinuationRecord ForJSObject(Tagged<JSAny> obj) {
    DCHECK(Is<JSObject>(obj));
    return RdnContinuationRecord(Type::kObject, obj, 0, 0, 0, 0,
                                 Tagged<DescriptorArray>());
  }
  template <DescriptorArray::FastIterableState fast_iterable_state>
  static constexpr RdnContinuationRecord ForJSObjectResume(
      Tagged<JSAny> obj, uint16_t descriptor_idx, uint16_t nof_descriptors,
      uint8_t in_object_properties, uint8_t in_object_properties_start,
      Tagged<DescriptorArray> descriptors) {
    DCHECK(Is<JSObject>(obj));
    Type type;
    using enum DescriptorArray::FastIterableState;
    switch (fast_iterable_state) {
      case kJsonFast: type = Type::kObjectResume_FastIterable; break;
      case kJsonSlow: type = Type::kObjectResume_SlowIterable; break;
      case kUnknown: type = Type::kObjectResume_Uninitialized; break;
    }
    return RdnContinuationRecord(type, obj, descriptor_idx, nof_descriptors,
                                 in_object_properties,
                                 in_object_properties_start, descriptors);
  }
  static constexpr RdnContinuationRecord ForObjectKey(Tagged<String> key,
                                                      bool comma) {
    return RdnContinuationRecord(Type::kObjectKey, key, comma);
  }

  Type type() const { return type_; }
  Tagged<ObjectT> object() const { return object_; }
  Tagged<JSAny> simple_object() const {
    DCHECK_EQ(type(), Type::kSimpleObject);
    return Cast<JSAny>(object_);
  }
  Tagged<JSArray> js_array() const {
    DCHECK_EQ(type(), Type::kArray);
    return Cast<JSArray>(object_);
  }
  Tagged<FixedArrayBase> array_elements() const {
    DCHECK(IsArrayResumeType(type()));
    return Cast<FixedArrayBase>(object_);
  }
  Tagged<JSObject> js_object() const {
    DCHECK(type() == Type::kObject || IsObjectResumeType(type()));
    return Cast<JSObject>(object_);
  }
  Tagged<String> object_key() const {
    DCHECK_EQ(type(), Type::kObjectKey);
    return Cast<String>(object_);
  }
  uint32_t array_index() const {
    DCHECK(IsArrayResumeType(type()));
    return js_array_.index;
  }
  uint32_t array_length() const {
    DCHECK(IsArrayResumeType(type()));
    return js_array_.length;
  }
  uint16_t object_descriptor_idx() const {
    DCHECK(IsObjectResumeType(type()));
    return js_object_.descriptor_idx;
  }
  uint16_t object_nof_descriptors() const {
    DCHECK(IsObjectResumeType(type()));
    return js_object_.nof_descriptors;
  }
  uint8_t object_in_object_properties() const {
    DCHECK(IsObjectResumeType(type()));
    return js_object_.in_object_properties;
  }
  uint8_t object_in_object_properties_start() const {
    DCHECK(IsObjectResumeType(type()));
    return js_object_.in_object_properties_start;
  }
  Tagged<DescriptorArray> object_descriptors() const {
    DCHECK(IsObjectResumeType(type()));
    return js_object_.descriptors;
  }
  bool object_key_comma() const {
    DCHECK_EQ(type(), Type::kObjectKey);
    return object_key_.comma;
  }

  static constexpr bool IsObjectResumeType(Type type) {
    return type == Type::kObjectResume_FastIterable ||
           type == Type::kObjectResume_SlowIterable ||
           type == Type::kObjectResume_Uninitialized;
  }
  static constexpr bool IsArrayResumeType(Type type) {
    return type == Type::kArrayResume || type == Type::kArrayResume_Holey ||
           type == Type::kArrayResume_WithInterrupts ||
           type == Type::kArrayResume_Holey_WithInterrupts;
  }

 private:
  constexpr RdnContinuationRecord(Type type, Tagged<ObjectT> obj,
                                  uint32_t index, uint32_t length)
      : type_(type), object_(obj), js_array_({index, length}) {}
  constexpr RdnContinuationRecord(Type type, Tagged<ObjectT> obj,
                                  uint16_t descriptor_idx,
                                  uint16_t nof_descriptors,
                                  uint8_t in_object_properties,
                                  uint8_t in_object_properties_start,
                                  Tagged<DescriptorArray> descriptors)
      : type_(type),
        object_(obj),
        js_object_({descriptor_idx, nof_descriptors, in_object_properties,
                    in_object_properties_start, descriptors}) {}
  constexpr RdnContinuationRecord(Type type, Tagged<ObjectT> obj, bool comma)
      : type_(type), object_(obj), object_key_{comma} {}

  static constexpr Type ContinuationTypeFromResult(
      FastRdnStringifierResult result) {
    DCHECK(result == JS_OBJECT || result == JS_ARRAY);
    static_assert(JS_OBJECT - 1 == Type::kObject);
    static_assert(JS_ARRAY - 1 == Type::kArray);
    return static_cast<Type>(result - 1);
  }
  static consteval Type ContinuationTypeForArray(ElementsKind kind,
                                                 bool with_interrupt_check) {
    DCHECK(IsObjectElementsKind(kind));
    if (IsHoleyElementsKind(kind)) {
      return with_interrupt_check ? kArrayResume_Holey_WithInterrupts
                                  : kArrayResume_Holey;
    } else {
      return with_interrupt_check ? kArrayResume_WithInterrupts
                                  : kArrayResume;
    }
  }

  Type type_;
  Tagged<ObjectT> object_;
  union {
    struct { uint32_t index; uint32_t length; } js_array_;
    struct {
      uint16_t descriptor_idx;
      uint16_t nof_descriptors;
      uint8_t in_object_properties;
      uint8_t in_object_properties_start;
      Tagged<DescriptorArray> descriptors;
    } js_object_;
    struct { bool comma; } object_key_;
  };
};

// ── Helpers ──

size_t RdnMaxEscapedStringLength(size_t length) { return length << 3; }

bool RdnIsFastKey(Tagged<String> key, const DisallowGarbageCollection& no_gc) {
  if (IsSeqOneByteString(key)) {
    Tagged<SeqOneByteString> seq = Cast<SeqOneByteString>(key);
    return DoNotEscapeString(seq->GetChars(no_gc), seq->length());
  }
  if (IsExternalOneByteString(key)) {
    Tagged<ExternalOneByteString> ext = Cast<ExternalOneByteString>(key);
    return DoNotEscapeString(ext->GetChars(), ext->length());
  }
  return false;
}

V8_INLINE bool CanFastSerializeRdnJSArrayFastPath(
    Tagged<JSArray> object, Tagged<HeapObject> initial_proto, Isolate* isolate) {
  Tagged<HeapObject> proto = object->map()->prototype();
  return V8_LIKELY(proto == initial_proto);
}

V8_INLINE bool CanFastSerializeRdnJSObjectFastPath(
    Tagged<JSObject> object, Tagged<HeapObject> initial_proto, Tagged<Map> map,
    Isolate* isolate) {
  if (V8_UNLIKELY(IsCustomElementsReceiverMap(map))) return false;
  if (V8_UNLIKELY(!object->HasFastProperties())) return false;
  auto roots = ReadOnlyRoots(isolate);
  auto elements = object->elements();
  if (V8_UNLIKELY(elements != roots.empty_fixed_array() &&
                  elements != roots.empty_slow_element_dictionary())) {
    return false;
  }
  Tagged<HeapObject> proto = map->prototype();
  return V8_LIKELY(proto == initial_proto);
}

// ── FastRdnStringifier class ──

template <typename Char>
class FastRdnStringifier {
 public:
  explicit FastRdnStringifier(Isolate* isolate);
  size_t ResultLength() const { return buffer_.length(); }
  template <typename DstChar>
  void CopyResultTo(DstChar* out_buffer) { buffer_.CopyTo(out_buffer); }
  V8_INLINE FastRdnStringifierResult
  SerializeObject(Tagged<JSAny> object, const DisallowGarbageCollection& no_gc);
  template <typename OldChar>
    requires(sizeof(OldChar) < sizeof(Char))
  V8_NOINLINE FastRdnStringifierResult
  ResumeFrom(FastRdnStringifier<OldChar>& old,
             const DisallowGarbageCollection& no_gc);

 private:
  static constexpr bool is_one_byte = sizeof(Char) == sizeof(uint8_t);
  V8_INLINE void SeparatorUnchecked(bool comma) {
    if (comma) AppendCharacterUnchecked(',');
  }
  V8_INLINE void Separator(bool comma) {
    if (comma) AppendCharacter(',');
  }
  V8_INLINE void EnsureCapacity(size_t size) { buffer_.EnsureCapacity(size); }
  template <typename SrcChar>
  V8_INLINE void AppendCharacterUnchecked(SrcChar c) {
    buffer_.AppendCharacter(c);
  }
  template <typename SrcChar>
  V8_INLINE void AppendCharacter(SrcChar c) {
    EnsureCapacity(1);
    AppendCharacterUnchecked(c);
  }
  template <size_t N>
  V8_INLINE void AppendCStringLiteralUnchecked(const char (&literal)[N]) {
    constexpr size_t length = N - 1;
    static_assert(length > 0);
    if constexpr (length == 1) return AppendCharacterUnchecked(literal[0]);
    buffer_.Append(reinterpret_cast<const uint8_t*>(literal), length);
  }
  template <size_t N>
  V8_INLINE void AppendCStringLiteral(const char (&literal)[N]) {
    constexpr size_t length = N - 1;
    static_assert(length > 0);
    EnsureCapacity(length);
    AppendCStringLiteralUnchecked(literal);
  }
  V8_INLINE void AppendCStringUnchecked(const char* chars, size_t len) {
    buffer_.Append(reinterpret_cast<const unsigned char*>(chars), len);
  }
  V8_INLINE void AppendCStringUnchecked(const char* chars) {
    AppendCStringUnchecked(chars, strlen(chars));
  }
  V8_INLINE void AppendStringUnchecked(std::string_view str) {
    AppendCStringUnchecked(str.data(), str.length());
  }
  V8_INLINE void AppendCString(const char* chars, size_t len) {
    EnsureCapacity(len);
    AppendCStringUnchecked(chars, len);
  }
  V8_INLINE void AppendString(std::string_view str) {
    AppendCString(str.data(), str.length());
  }

  V8_INLINE void SerializeSmi(Tagged<Smi> object);
  void SerializeDouble(double number);
  void SerializeDate(Tagged<JSDate> date);
  template <bool no_escaping>
  FastRdnStringifierObjectKeyResult SerializeObjectKey(
      Tagged<String> key, bool comma, const DisallowGarbageCollection& no_gc);
  template <typename StringT, bool no_escaping>
  FastRdnStringifierObjectKeyResult SerializeObjectKey(
      Tagged<String> key, bool comma, const DisallowGarbageCollection& no_gc);
  template <typename StringT>
  V8_INLINE FastRdnStringifierResult SerializeString(
      Tagged<HeapObject> str, const DisallowGarbageCollection& no_gc);
  FastRdnStringifierResult TrySerializeSimpleObject(Tagged<JSAny> object);
  FastRdnStringifierResult SerializeObject(
      RdnContinuationRecord cont, const DisallowGarbageCollection& no_gc);
  V8_INLINE FastRdnStringifierResult SerializeJSObject(
      Tagged<JSObject> obj, const DisallowGarbageCollection& no_gc);
  template <DescriptorArray::FastIterableState fast_iterable_state>
  V8_INLINE FastRdnStringifierResult ResumeJSObject(
      Tagged<JSObject> obj, uint16_t start_descriptor_idx,
      uint16_t nof_descriptors, uint8_t in_object_properties,
      uint8_t in_object_properties_start, Tagged<DescriptorArray> descriptors,
      bool comma, const DisallowGarbageCollection& no_gc);
  FastRdnStringifierResult SerializeJSArray(Tagged<JSArray> array);
  template <ElementsKind kind>
  FastRdnStringifierResult SerializeFixedArrayWithInterruptCheck(
      Tagged<FixedArrayBase> elements, uint32_t start_index, uint32_t length);
  template <ElementsKind kind>
  V8_INLINE FastRdnStringifierResult SerializeFixedArray(
      Tagged<FixedArrayBase> array, uint32_t start_idx, uint32_t length);
  template <ElementsKind kind, bool with_interrupt_checks, typename T>
  V8_INLINE FastRdnStringifierResult
  SerializeFixedArrayElement(Tagged<T> elements, uint32_t i, uint32_t length);
  V8_NOINLINE FastRdnStringifierResult HandleInterruptAndCheckCycle();
  V8_NOINLINE bool CheckCycle();

  template <typename SrcChar>
    requires(sizeof(SrcChar) == sizeof(uint8_t))
  V8_INLINE bool AppendString(const SrcChar* chars, size_t length,
                              const DisallowGarbageCollection& no_gc);
  template <typename SrcChar>
  V8_INLINE void AppendStringNoEscapes(const SrcChar* chars, size_t length,
                                       const DisallowGarbageCollection& no_gc);
  template <typename SrcChar>
    requires(sizeof(SrcChar) == sizeof(uint8_t))
  bool AppendStringScalar(const SrcChar* chars, size_t length, size_t start,
                          size_t uncopied_src_index,
                          const DisallowGarbageCollection& no_gc);
  template <typename SrcChar>
    requires(sizeof(SrcChar) == sizeof(uint8_t))
  V8_INLINE bool AppendStringSWAR(const SrcChar* chars, size_t length,
                                  size_t start, size_t uncopied_src_index,
                                  const DisallowGarbageCollection& no_gc);
  template <typename SrcChar>
    requires(sizeof(SrcChar) == sizeof(uint8_t))
  V8_INLINE bool AppendStringSIMD(const SrcChar* chars, size_t length,
                                  const DisallowGarbageCollection& no_gc);
  template <typename SrcChar>
    requires(sizeof(SrcChar) == sizeof(base::uc16))
  V8_INLINE bool AppendString(const SrcChar* chars, size_t length,
                              const DisallowGarbageCollection& no_gc);

  using FastIterableState = DescriptorArray::FastIterableState;
  static constexpr uint32_t kGlobalInterruptBudget = 200000;
  static constexpr uint32_t kArrayInterruptLength = 4000;

  Isolate* isolate_;
  RdnOutBuffer<Char> buffer_;
  base::SmallVector<RdnContinuationRecord, 16> stack_;
  Tagged<HeapObject> initial_jsobject_proto_;
  Tagged<HeapObject> initial_jsarray_proto_;
  template <typename> friend class FastRdnStringifier;
};

// ── Constructor ──

template <typename Char>
FastRdnStringifier<Char>::FastRdnStringifier(Isolate* isolate)
    : isolate_(isolate), buffer_(isolate->allocator()) {}

// ── Leaf serializers ──

template <typename Char>
void FastRdnStringifier<Char>::SerializeSmi(Tagged<Smi> object) {
  static_assert(Smi::kMaxValue <= 2147483647);
  static_assert(Smi::kMinValue >= -2147483648);
  static constexpr uint32_t kBufferSize = sizeof("-2147483648") - 1;
  char chars[kBufferSize];
  base::Vector<char> buffer(chars, kBufferSize);
  std::string_view str = IntToStringView(object.value(), buffer);
  AppendString(str);
}

template <typename Char>
void FastRdnStringifier<Char>::SerializeDouble(double number) {
  // RDN: NaN and Infinity are literals, not "null".
  if (V8_UNLIKELY(std::isnan(number))) {
    AppendCStringLiteral("NaN");
    return;
  }
  if (V8_UNLIKELY(std::isinf(number))) {
    if (number > 0) {
      AppendCStringLiteral("Infinity");
    } else {
      AppendCStringLiteral("-Infinity");
    }
    return;
  }
  static constexpr uint32_t kBufferSize = 100;
  char chars[kBufferSize];
  base::Vector<char> buffer(chars, kBufferSize);
  std::string_view str = DoubleToStringView(number, buffer);
  AppendString(str);
}

template <typename Char>
void FastRdnStringifier<Char>::SerializeDate(Tagged<JSDate> date) {
  double value = date->value();
  if (std::isnan(value)) {
    AppendCStringLiteral("null");
    return;
  }
  int64_t time_ms = static_cast<int64_t>(value);
  static constexpr int kMsPerSecond = 1000;
  static constexpr int kMsPerMinute = 60 * kMsPerSecond;
  static constexpr int kMsPerHour = 60 * kMsPerMinute;
  static constexpr int64_t kMsPerDay = 24 * kMsPerHour;
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
  // Civil date from days since epoch (Howard Hinnant's algorithm).
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
  // @YYYY-MM-DDTHH:mm:ss.sssZ = exactly 25 chars.
  // Direct digit-pair writing: ~10ns vs ~100-200ns for snprintf.
  char buf[25];
  FormatDateDirect(buf, y, static_cast<int>(m), static_cast<int>(d),
                   hour, min, sec, ms);
  AppendCString(buf, 25);
}

// ── String serialization (SIMD/SWAR/Scalar with RdnEscapeTable) ──

template <typename Char>
template <typename SrcChar>
  requires(sizeof(SrcChar) == sizeof(uint8_t))
bool FastRdnStringifier<Char>::AppendString(
    const SrcChar* chars, size_t length,
    const DisallowGarbageCollection& no_gc) {
  constexpr int kUseSimdLengthThreshold = 32;
  if (length >= kUseSimdLengthThreshold) {
    return AppendStringSIMD(chars, length, no_gc);
  }
  return AppendStringSWAR(chars, length, 0, 0, no_gc);
}

template <typename Char>
template <typename SrcChar>
void FastRdnStringifier<Char>::AppendStringNoEscapes(
    const SrcChar* chars, size_t length,
    const DisallowGarbageCollection& no_gc) {
  buffer_.Append(chars, length);
}

template <typename Char>
template <typename SrcChar>
  requires(sizeof(SrcChar) == sizeof(uint8_t))
bool FastRdnStringifier<Char>::AppendStringScalar(
    const SrcChar* chars, size_t length, size_t start,
    size_t uncopied_src_index, const DisallowGarbageCollection& no_gc) {
  bool needs_escaping = false;
  for (size_t i = start; i < length; i++) {
    SrcChar c = chars[i];
    if (V8_LIKELY(DoNotEscape(c))) continue;
    needs_escaping = true;
    buffer_.Append(chars + uncopied_src_index, i - uncopied_src_index);
    AppendCStringUnchecked(
        &RdnEscapeTable[c * kRdnEscapeTableEntrySize]);
    uncopied_src_index = i + 1;
  }
  if (V8_LIKELY(uncopied_src_index < length)) {
    buffer_.Append(chars + uncopied_src_index, length - uncopied_src_index);
  }
  return needs_escaping;
}

template <typename Char>
template <typename SrcChar>
  requires(sizeof(SrcChar) == sizeof(uint8_t))
V8_CLANG_NO_SANITIZE("alignment")
bool FastRdnStringifier<Char>::AppendStringSWAR(
    const SrcChar* chars, size_t length, size_t start,
    size_t uncopied_src_index, const DisallowGarbageCollection& no_gc) {
  using PackedT = uint32_t;
  static constexpr size_t stride = sizeof(PackedT);
  size_t i = start;
  for (; i + (stride - 1) < length; i += stride) {
    PackedT packed = *reinterpret_cast<const PackedT*>(chars + i);
    if (V8_UNLIKELY(NeedsEscape(packed))) break;
  }
  return AppendStringScalar(chars, length, i, uncopied_src_index, no_gc);
}

template <typename Char>
template <typename SrcChar>
  requires(sizeof(SrcChar) == sizeof(uint8_t))
bool FastRdnStringifier<Char>::AppendStringSIMD(
    const SrcChar* chars, size_t length,
    const DisallowGarbageCollection& no_gc) {
  namespace hw = hwy::HWY_NAMESPACE;
  bool needs_escaping = false;
  size_t uncopied_src_index = 0;
  const SrcChar* block = chars;
  const SrcChar* end = chars + length;
  hw::FixedTag<SrcChar, 16> tag;
  static const size_t stride = hw::Lanes(tag);
  const auto mask_0x20 = hw::Set(tag, 0x20);
  const auto mask_0x22 = hw::Set(tag, 0x22);
  const auto mask_0x5c = hw::Set(tag, 0x5c);
  for (; block + (stride - 1) < end; block += stride) {
    const auto input = hw::LoadU(tag, block);
    const auto has_lower_than_0x20 = hw::Lt(input, mask_0x20);
    const auto has_0x22 = hw::Eq(input, mask_0x22);
    const auto has_0x5c = hw::Eq(input, mask_0x5c);
    const auto result =
        hw::Or(hw::Or(has_lower_than_0x20, has_0x22), has_0x5c);
    if (V8_LIKELY(hw::AllFalse(tag, result))) continue;
    needs_escaping = true;
    size_t index = hw::FindKnownFirstTrue(tag, result);
    Char found_char = block[index];
    const size_t char_index = block - chars + index;
    buffer_.Append(chars + uncopied_src_index,
                   char_index - uncopied_src_index);
    DCHECK_LT(found_char, 0x60);
    AppendCStringUnchecked(
        &RdnEscapeTable[found_char * kRdnEscapeTableEntrySize]);
    uncopied_src_index = char_index + 1;
    block += index + 1;
    block -= stride;
  }
  const size_t start_index = block - chars;
  return AppendStringSWAR(chars, length, start_index, uncopied_src_index,
                          no_gc) ||
         needs_escaping;
}

template <typename Char>
template <typename SrcChar>
  requires(sizeof(SrcChar) == sizeof(base::uc16))
bool FastRdnStringifier<Char>::AppendString(
    const SrcChar* chars, size_t length,
    const DisallowGarbageCollection& no_gc) {
  bool needs_escaping = false;
  uint32_t uncopied_src_index = 0;
  for (uint32_t i = 0; i < length; i++) {
    SrcChar c = chars[i];
    if (V8_LIKELY(DoNotEscape(c))) continue;
    needs_escaping = true;
    if (sizeof(SrcChar) != 1 &&
        base::IsInRange(c, static_cast<SrcChar>(0xD800),
                        static_cast<SrcChar>(0xDFFF))) {
      buffer_.Append(chars + uncopied_src_index, i - uncopied_src_index);
      char double_to_radix_chars[kDoubleToRadixMaxChars];
      base::Vector<char> double_to_radix_buffer =
          base::ArrayVector(double_to_radix_chars);
      if (c <= 0xDBFF) {
        if (i + 1 < length) {
          SrcChar next = chars[i + 1];
          if (base::IsInRange(next, static_cast<SrcChar>(0xDC00),
                              static_cast<SrcChar>(0xDFFF))) {
            AppendCharacterUnchecked(c);
            AppendCharacterUnchecked(next);
            i++;
          } else {
            AppendCStringLiteralUnchecked("\\u");
            AppendStringUnchecked(
                DoubleToRadixStringView(c, 16, double_to_radix_buffer));
          }
        } else {
          AppendCStringLiteralUnchecked("\\u");
          AppendStringUnchecked(
              DoubleToRadixStringView(c, 16, double_to_radix_buffer));
        }
      } else {
        AppendCStringLiteralUnchecked("\\u");
        AppendStringUnchecked(
            DoubleToRadixStringView(c, 16, double_to_radix_buffer));
      }
      uncopied_src_index = i + 1;
    } else {
      buffer_.Append(chars + uncopied_src_index, i - uncopied_src_index);
      DCHECK_LT(c, 0x60);
      AppendCStringUnchecked(
          &RdnEscapeTable[c * kRdnEscapeTableEntrySize]);
      uncopied_src_index = i + 1;
    }
  }
  if (uncopied_src_index < length) {
    buffer_.Append(chars + uncopied_src_index, length - uncopied_src_index);
  }
  return needs_escaping;
}

// ── Object key serialization ──

template <typename Char>
template <bool no_escaping>
FastRdnStringifierObjectKeyResult
FastRdnStringifier<Char>::SerializeObjectKey(
    Tagged<String> key, bool comma, const DisallowGarbageCollection& no_gc) {
#if V8_STATIC_ROOTS_BOOL
  ReadOnlyRoots roots(isolate_);
  Tagged<Map> map = key->map();
  if (map == roots.internalized_one_byte_string_map()) {
    V8_INLINE_STATEMENT return SerializeObjectKey<SeqOneByteString,
                                                  no_escaping>(key, comma,
                                                               no_gc);
  } else if (map == roots.external_internalized_one_byte_string_map() ||
             map ==
                 roots.uncached_external_internalized_one_byte_string_map()) {
    V8_INLINE_STATEMENT return SerializeObjectKey<ExternalOneByteString,
                                                  no_escaping>(key, comma,
                                                               no_gc);
  } else {
    if constexpr (is_one_byte) {
      DCHECK(InstanceTypeChecker::IsTwoByteString(map));
      if constexpr (no_escaping) {
        UNREACHABLE();
      } else {
        return FastRdnStringifierObjectKeyResult::kChangeEncoding;
      }
    } else {
      if (map == roots.internalized_two_byte_string_map()) {
        return SerializeObjectKey<SeqTwoByteString, no_escaping>(key, comma,
                                                                 no_gc);
      } else if (
          map == roots.external_internalized_two_byte_string_map() ||
          map == roots.uncached_external_internalized_two_byte_string_map()) {
        return SerializeObjectKey<ExternalTwoByteString, no_escaping>(
            key, comma, no_gc);
      }
    }
  }
#else
  InstanceType instance_type = key->map()->instance_type();
  switch (instance_type) {
    case INTERNALIZED_ONE_BYTE_STRING_TYPE:
      V8_INLINE_STATEMENT return SerializeObjectKey<SeqOneByteString,
                                                    no_escaping>(key, comma,
                                                                 no_gc);
    case EXTERNAL_INTERNALIZED_ONE_BYTE_STRING_TYPE:
    case UNCACHED_EXTERNAL_INTERNALIZED_ONE_BYTE_STRING_TYPE:
      V8_INLINE_STATEMENT return SerializeObjectKey<ExternalOneByteString,
                                                    no_escaping>(key, comma,
                                                                 no_gc);
    case INTERNALIZED_TWO_BYTE_STRING_TYPE:
      return SerializeObjectKey<SeqTwoByteString, no_escaping>(key, comma,
                                                               no_gc);
    case EXTERNAL_INTERNALIZED_TWO_BYTE_STRING_TYPE:
    case UNCACHED_EXTERNAL_INTERNALIZED_TWO_BYTE_STRING_TYPE:
      return SerializeObjectKey<ExternalTwoByteString, no_escaping>(key, comma,
                                                                    no_gc);
    default:
      UNREACHABLE();
  }
#endif
  UNREACHABLE();
}

template <typename Char>
template <typename StringT, bool no_escaping>
FastRdnStringifierObjectKeyResult
FastRdnStringifier<Char>::SerializeObjectKey(
    Tagged<String> obj, bool comma, const DisallowGarbageCollection& no_gc) {
  using StringChar = StringT::Char;
  if constexpr (is_one_byte && sizeof(StringChar) == 2) {
    if constexpr (no_escaping) {
      UNREACHABLE();
    } else {
      return FastRdnStringifierObjectKeyResult::kChangeEncoding;
    }
  } else {
    Tagged<StringT> string = Cast<StringT>(obj);
    const StringChar* chars;
    if constexpr (requires { string->GetChars(no_gc); }) {
      chars = string->GetChars(no_gc);
    } else {
      chars = string->GetChars();
    }
    const uint32_t length = string->length();
    size_t max_length;
    if constexpr (no_escaping) {
      max_length = length;
    } else {
      max_length = RdnMaxEscapedStringLength(length);
    }
    max_length += 4;
    EnsureCapacity(max_length);
    SeparatorUnchecked(comma);
    AppendCharacterUnchecked('"');
    FastRdnStringifierObjectKeyResult result;
    if constexpr (no_escaping) {
      DCHECK(RdnIsFastKey(obj, no_gc));
      AppendStringNoEscapes(chars, length, no_gc);
      result = FastRdnStringifierObjectKeyResult::kSuccess;
    } else {
      bool needs_escaping = AppendString(chars, length, no_gc);
      result = sizeof(StringChar) == 1 && !needs_escaping
                   ? FastRdnStringifierObjectKeyResult::kSuccess
                   : FastRdnStringifierObjectKeyResult::kSlow;
    }
    AppendCharacterUnchecked('"');
    AppendCharacterUnchecked(':');
    return result;
  }
}

// ── String value serialization ──

template <typename Char>
template <typename StringT>
FastRdnStringifierResult FastRdnStringifier<Char>::SerializeString(
    Tagged<HeapObject> obj, const DisallowGarbageCollection& no_gc) {
  using StringChar = StringT::Char;
  if constexpr (is_one_byte && sizeof(StringChar) == 2) {
    return CHANGE_ENCODING;
  } else {
    Tagged<StringT> string = Cast<StringT>(obj);
    const StringChar* chars;
    if constexpr (requires { string->GetChars(no_gc); }) {
      chars = string->GetChars(no_gc);
    } else {
      chars = string->GetChars();
    }
    const uint32_t length = string->length();
    EnsureCapacity(RdnMaxEscapedStringLength(length) + 2);
    AppendCharacterUnchecked('"');
    AppendString(chars, length, no_gc);
    AppendCharacterUnchecked('"');
    return SUCCESS;
  }
}

// ── Type dispatch ──

template <typename Char>
FastRdnStringifierResult FastRdnStringifier<Char>::TrySerializeSimpleObject(
    Tagged<JSAny> object) {
  DisallowGarbageCollection no_gc;
  DisableGCMole no_gc_mole;
  if (IsSmi(object)) {
    SerializeSmi(Cast<Smi>(object));
    return SUCCESS;
  }
  Tagged<HeapObject> obj = Cast<HeapObject>(object);
  Tagged<Map> map = obj->map();
  InstanceType instance_type = map->instance_type();
  switch (instance_type) {
    case INTERNALIZED_ONE_BYTE_STRING_TYPE:
    case SEQ_ONE_BYTE_STRING_TYPE:
      return SerializeString<SeqOneByteString>(obj, no_gc);
    case EXTERNAL_INTERNALIZED_ONE_BYTE_STRING_TYPE:
    case UNCACHED_EXTERNAL_INTERNALIZED_ONE_BYTE_STRING_TYPE:
    case EXTERNAL_ONE_BYTE_STRING_TYPE:
    case UNCACHED_EXTERNAL_ONE_BYTE_STRING_TYPE:
      return SerializeString<ExternalOneByteString>(obj, no_gc);
    case THIN_ONE_BYTE_STRING_TYPE: {
      Tagged<String> actual = Cast<ThinString>(obj)->actual();
      if (IsExternalString(actual)) {
        return SerializeString<ExternalOneByteString>(actual, no_gc);
      } else {
        return SerializeString<SeqOneByteString>(actual, no_gc);
      }
    }
    case INTERNALIZED_TWO_BYTE_STRING_TYPE:
    case SEQ_TWO_BYTE_STRING_TYPE:
      return SerializeString<SeqTwoByteString>(obj, no_gc);
    case EXTERNAL_INTERNALIZED_TWO_BYTE_STRING_TYPE:
    case UNCACHED_EXTERNAL_INTERNALIZED_TWO_BYTE_STRING_TYPE:
    case EXTERNAL_TWO_BYTE_STRING_TYPE:
    case UNCACHED_EXTERNAL_TWO_BYTE_STRING_TYPE:
      return SerializeString<ExternalTwoByteString>(obj, no_gc);
    case THIN_TWO_BYTE_STRING_TYPE: {
      if constexpr (is_one_byte) {
        return CHANGE_ENCODING;
      } else {
        Tagged<String> actual = Cast<ThinString>(obj)->actual();
        if (IsExternalString(actual)) {
          return SerializeString<ExternalTwoByteString>(actual, no_gc);
        } else {
          return SerializeString<SeqTwoByteString>(actual, no_gc);
        }
      }
    }
    case HEAP_NUMBER_TYPE:
      SerializeDouble(Cast<HeapNumber>(obj)->value());
      return SUCCESS;
    case ODDBALL_TYPE:
      switch (Cast<Oddball>(obj)->kind()) {
        case Oddball::kFalse:
          AppendCStringLiteral("false");
          return SUCCESS;
        case Oddball::kTrue:
          AppendCStringLiteral("true");
          return SUCCESS;
        case Oddball::kNull:
          AppendCStringLiteral("null");
          return SUCCESS;
        default:
          return UNDEFINED;
      }
    case SYMBOL_TYPE:
      return UNDEFINED;
    case JS_DATE_TYPE:
      // RDN: Inline GC-free date serialization.
      SerializeDate(Cast<JSDate>(obj));
      return SUCCESS;
    case JS_FUNCTION_TYPE:
      // RDN: Functions are skipped (like undefined).
      return UNDEFINED;
    case JS_OBJECT_TYPE:
      return JS_OBJECT;
    case JS_ARRAY_TYPE:
      return JS_ARRAY;
    case BIGINT_TYPE: {
      // RDN: Serialize small BigInts directly via IntToStringView + 'n'.
      // Falls to SLOW_PATH for large BigInts that don't fit in int64.
      Tagged<BigInt> bigint = Cast<BigInt>(obj);
      bool lossless = false;
      int64_t value = bigint->AsInt64(&lossless);
      if (lossless) {
        static constexpr uint32_t kBigIntBufferSize =
            sizeof("-9223372036854775808") - 1;
        char chars[kBigIntBufferSize];
        base::Vector<char> buf(chars, kBigIntBufferSize);
        // Use snprintf for int64_t since IntToStringView only handles int.
        int len = snprintf(chars, kBigIntBufferSize, "%" PRId64, value);
        AppendCString(chars, len);
        AppendCharacter('n');
        return SUCCESS;
      }
      return SLOW_PATH;
    }
    case JS_REG_EXP_TYPE: {
      // RDN: GC-free RegExp serialization — read source() and flags()
      // directly from the JSRegExp object.
      Tagged<JSRegExp> regexp = Cast<JSRegExp>(obj);
      Tagged<String> source = regexp->source();
      JSRegExp::Flags flags = regexp->flags();

      // Write /pattern/flags without GC.
      AppendCharacter('/');
      if (source->length() > 0) {
        if (source->IsOneByteRepresentation()) {
          if (IsExternalString(source)) {
            auto result =
                SerializeString<ExternalOneByteString>(source, no_gc);
            if (result != SUCCESS) return result;
          } else {
            auto result = SerializeString<SeqOneByteString>(source, no_gc);
            if (result != SUCCESS) return result;
          }
        } else {
          if constexpr (is_one_byte) {
            return SLOW_PATH;
          } else {
            if (IsExternalString(source)) {
              auto result =
                  SerializeString<ExternalTwoByteString>(source, no_gc);
              if (result != SUCCESS) return result;
            } else {
              auto result = SerializeString<SeqTwoByteString>(source, no_gc);
              if (result != SUCCESS) return result;
            }
          }
        }
      }
      AppendCharacter('/');

      // Write flags in canonical order.
      if (flags & JSRegExp::kHasIndices) AppendCharacter('d');
      if (flags & JSRegExp::kGlobal) AppendCharacter('g');
      if (flags & JSRegExp::kIgnoreCase) AppendCharacter('i');
      if (flags & JSRegExp::kMultiline) AppendCharacter('m');
      if (flags & JSRegExp::kDotAll) AppendCharacter('s');
      if (flags & JSRegExp::kUnicode) AppendCharacter('u');
      if (flags & JSRegExp::kUnicodeSets) AppendCharacter('v');
      if (flags & JSRegExp::kSticky) AppendCharacter('y');

      return SUCCESS;
    }
    default:
      // Map, Set, TypedArray, TimeOnly, Duration, etc.
      return SLOW_PATH;
  }
  UNREACHABLE();
}

// ── JSObject serialization ──

template <typename Char>
FastRdnStringifierResult FastRdnStringifier<Char>::SerializeJSObject(
    Tagged<JSObject> obj, const DisallowGarbageCollection& no_gc) {
  Tagged<Map> map = obj->map();
  if (V8_UNLIKELY(!CanFastSerializeRdnJSObjectFastPath(
          obj, initial_jsobject_proto_, map, isolate_))) {
    return SLOW_PATH;
  }
  AppendCharacter('{');
  const uint16_t nof_descriptors = map->NumberOfOwnDescriptors();
  const uint8_t in_object_properties = map->GetInObjectProperties();
  const uint8_t in_object_properties_start =
      map->GetInObjectPropertiesStartInWords();
  const Tagged<DescriptorArray> descriptors = map->instance_descriptors();
  FastIterableState fast_iterable_state = descriptors->fast_iterable();
  switch (fast_iterable_state) {
#define CASE(state)                                    \
  case FastIterableState::state:                       \
    return ResumeJSObject<FastIterableState::state>(   \
        obj, 0, nof_descriptors, in_object_properties, \
        in_object_properties_start, descriptors, false, no_gc)
    CASE(kUnknown);
    CASE(kJsonFast);
    CASE(kJsonSlow);
#undef CASE
  }
  UNREACHABLE();
}

template <typename Char>
template <DescriptorArray::FastIterableState fast_iterable_state>
FastRdnStringifierResult FastRdnStringifier<Char>::ResumeJSObject(
    Tagged<JSObject> obj, uint16_t start_descriptor_idx,
    uint16_t nof_descriptors, uint8_t in_object_properties,
    uint8_t in_object_properties_start, Tagged<DescriptorArray> descriptors,
    bool comma, const DisallowGarbageCollection& no_gc) {
  PtrComprCageBase cage_base = GetPtrComprCageBase();
  InternalIndex::Range range{start_descriptor_idx, nof_descriptors};
  for (InternalIndex i : range) {
    static_assert(kMaxNumberOfDescriptors <
                  std::numeric_limits<uint16_t>::max());
    DCHECK_LE(i.as_uint32(), kMaxNumberOfDescriptors);
    const uint16_t descriptor_idx = static_cast<uint16_t>(i.as_uint32());
    Tagged<Name> name = descriptors->GetKey(i);
    int property_index;
    if constexpr (fast_iterable_state != FastIterableState::kJsonFast) {
      if (V8_UNLIKELY(IsSymbol(name))) {
        if constexpr (fast_iterable_state == FastIterableState::kUnknown) {
          descriptors->set_fast_iterable(FastIterableState::kJsonSlow);
        }
        continue;
      }
      PropertyDetails details = descriptors->GetDetails(i);
      // RDN: DontEnum descriptors may indicate TimeOnly/Duration.
      // Bail to slow path for correct serialization.
      if (V8_UNLIKELY(details.IsDontEnum())) {
        if constexpr (fast_iterable_state == FastIterableState::kUnknown) {
          descriptors->set_fast_iterable(FastIterableState::kJsonSlow);
        }
        return SLOW_PATH;
      }
      if (V8_UNLIKELY(details.location() != PropertyLocation::kField)) {
        descriptors->set_fast_iterable(FastIterableState::kJsonSlow);
        return SLOW_PATH;
      }
      DCHECK_EQ(PropertyKind::kData, details.kind());
      property_index = details.field_index();
    } else {
      DCHECK_EQ(descriptor_idx, descriptors->GetDetails(i).field_index());
      property_index = descriptor_idx;
    }
    const bool is_inobject = property_index < in_object_properties;
    Tagged<JSAny> property;
    if (is_inobject) {
      int offset = (in_object_properties_start + property_index) * kTaggedSize;
      property = TaggedField<JSAny>::Relaxed_Load(cage_base, obj, offset);
    } else {
      property_index -= in_object_properties;
      property = obj->property_array(cage_base)->get(cage_base, property_index);
    }
    DCHECK(IsInternalizedString(name));
    Tagged<String> key_name = Cast<String>(name);
    if (V8_UNLIKELY(IsUndefined(property) || IsSymbol(property) ||
                    IsJSFunction(property))) {
      if constexpr (fast_iterable_state == FastIterableState::kUnknown) {
        if (!RdnIsFastKey(key_name, no_gc)) {
          descriptors->set_fast_iterable(FastIterableState::kJsonSlow);
        }
      }
      continue;
    }
    FastRdnStringifierObjectKeyResult key_result;
    if constexpr (fast_iterable_state == FastIterableState::kJsonFast) {
      V8_INLINE_STATEMENT key_result =
          SerializeObjectKey<true>(key_name, comma, no_gc);
      DCHECK_EQ(key_result, FastRdnStringifierObjectKeyResult::kSuccess);
    } else {
      key_result = SerializeObjectKey<false>(key_name, comma, no_gc);
      if (V8_UNLIKELY(key_result !=
                      FastRdnStringifierObjectKeyResult::kSuccess)) {
        descriptors->set_fast_iterable(FastIterableState::kJsonSlow);
        if constexpr (is_one_byte) {
          if (key_result ==
              FastRdnStringifierObjectKeyResult::kChangeEncoding) {
            stack_.emplace_back(
                RdnContinuationRecord::
                    ForJSObjectResume<fast_iterable_state>(
                        obj, descriptor_idx + 1, nof_descriptors,
                        in_object_properties, in_object_properties_start,
                        descriptors));
            if (IsJSObject(property)) {
              stack_.emplace_back(
                  RdnContinuationRecord::ForJSObject(property));
            } else if (IsJSArray(property)) {
              stack_.emplace_back(
                  RdnContinuationRecord::ForJSArray(property));
            } else {
              stack_.emplace_back(
                  RdnContinuationRecord::ForSimpleObject(property));
            }
            stack_.emplace_back(
                RdnContinuationRecord::ForObjectKey(key_name, comma));
            return CHANGE_ENCODING;
          }
        } else {
          DCHECK_NE(key_result,
                    FastRdnStringifierObjectKeyResult::kChangeEncoding);
        }
      }
    }
    DisableGCMole no_gc_mole;
    FastRdnStringifierResult result;
    if constexpr (fast_iterable_state == FastIterableState::kJsonFast) {
      V8_INLINE_STATEMENT result = TrySerializeSimpleObject(property);
    } else {
      result = TrySerializeSimpleObject(property);
    }
    switch (result) {
      case SUCCESS:
        comma = true;
        break;
      case UNDEFINED:
        break;
      case JS_OBJECT:
      case JS_ARRAY:
        stack_.push_back(
            RdnContinuationRecord::ForJSObjectResume<fast_iterable_state>(
                obj, descriptor_idx + 1, nof_descriptors, in_object_properties,
                in_object_properties_start, descriptors));
        stack_.push_back(RdnContinuationRecord::ForJSAny(property, result));
        return result;
      case CHANGE_ENCODING:
        if constexpr (is_one_byte) {
          stack_.push_back(
              RdnContinuationRecord::ForJSObjectResume<fast_iterable_state>(
                  obj, descriptor_idx + 1, nof_descriptors,
                  in_object_properties, in_object_properties_start,
                  descriptors));
          stack_.push_back(RdnContinuationRecord::ForSimpleObject(property));
          return result;
        } else {
          UNREACHABLE();
        }
      case SLOW_PATH:
      case EXCEPTION:
        return result;
    }
  }
  AppendCharacter('}');
  if constexpr (fast_iterable_state == FastIterableState::kUnknown) {
    if (nof_descriptors == descriptors->number_of_descriptors()) {
      descriptors->set_fast_iterable_if(FastIterableState::kJsonFast,
                                        FastIterableState::kUnknown);
    }
  }
  return SUCCESS;
}

// ── JSArray serialization ──

template <typename Char>
FastRdnStringifierResult FastRdnStringifier<Char>::SerializeJSArray(
    Tagged<JSArray> array) {
  if (V8_UNLIKELY(!CanFastSerializeRdnJSArrayFastPath(
          array, initial_jsarray_proto_, isolate_))) {
    return SLOW_PATH;
  }
  AppendCharacter('[');
  uint32_t length = static_cast<uint32_t>(Object::NumberValue(array->length()));
  Tagged<FixedArrayBase> elements = array->elements();
  switch (array->GetElementsKind()) {
#define CASE(kind)                                                             \
  case kind:                                                                   \
    if constexpr (IsHoleyElementsKind(kind)) {                                 \
      if (V8_UNLIKELY(!Protectors::IsNoElementsIntact(isolate_))) {            \
        return SLOW_PATH;                                                      \
      }                                                                        \
    }                                                                          \
    if (V8_UNLIKELY(length > kArrayInterruptLength)) {                         \
      return SerializeFixedArrayWithInterruptCheck<kind>(elements, 0, length); \
    } else {                                                                   \
      return SerializeFixedArray<kind>(elements, 0, length);                   \
    }
    CASE(PACKED_SMI_ELEMENTS)
    CASE(PACKED_ELEMENTS)
    CASE(PACKED_DOUBLE_ELEMENTS)
    CASE(HOLEY_SMI_ELEMENTS)
    CASE(HOLEY_ELEMENTS)
    CASE(HOLEY_DOUBLE_ELEMENTS)
#undef CASE
    default:
      return SLOW_PATH;
  }
  UNREACHABLE();
}

template <typename Char>
template <ElementsKind kind>
FastRdnStringifierResult
FastRdnStringifier<Char>::SerializeFixedArrayWithInterruptCheck(
    Tagged<FixedArrayBase> elements, uint32_t start_index, uint32_t length) {
  using ArrayT = std::conditional_t<IsDoubleElementsKind(kind),
                                    FixedDoubleArray, FixedArray>;
  StackLimitCheck interrupt_check(isolate_);
  uint32_t limit = std::min(length, start_index + kArrayInterruptLength);
  constexpr uint32_t kMaxAllowedFastPackedLength =
      std::numeric_limits<uint32_t>::max() - kArrayInterruptLength;
  static_assert(FixedArray::kMaxLength < kMaxAllowedFastPackedLength);
  DisableGCMole no_gc_mole;
  uint32_t i = start_index;
  while (true) {
    for (; i < limit; i++) {
      FastRdnStringifierResult result =
          SerializeFixedArrayElement<kind, true>(
              Cast<ArrayT>(elements), i, length);
      if (result != SUCCESS) return result;
    }
    if (i >= length) {
      AppendCharacter(']');
      return SUCCESS;
    }
    DCHECK_LT(limit, kMaxAllowedFastPackedLength);
    limit = std::min(length, limit + kArrayInterruptLength);
    {
      AllowGarbageCollection allow_gc;
      if (interrupt_check.InterruptRequested() &&
          IsExceptionHole(isolate_->stack_guard()->HandleInterrupts(
                              StackGuard::InterruptLevel::kNoGC),
                          isolate_)) {
        return EXCEPTION;
      }
    }
  }
  UNREACHABLE();
}

template <typename Char>
template <ElementsKind kind>
FastRdnStringifierResult FastRdnStringifier<Char>::SerializeFixedArray(
    Tagged<FixedArrayBase> elements, uint32_t start_index, uint32_t length) {
  using ArrayT = std::conditional_t<IsDoubleElementsKind(kind),
                                    FixedDoubleArray, FixedArray>;
  for (uint32_t i = start_index; i < length; i++) {
    FastRdnStringifierResult result =
        SerializeFixedArrayElement<kind, false>(
            Cast<ArrayT>(elements), i, length);
    if (result != SUCCESS) return result;
  }
  AppendCharacter(']');
  return SUCCESS;
}

template <typename Char>
template <ElementsKind kind, bool with_interrupt_checks, typename T>
FastRdnStringifierResult
FastRdnStringifier<Char>::SerializeFixedArrayElement(
    Tagged<T> elements, uint32_t i, uint32_t length) {
  if constexpr (IsHoleyElementsKind(kind)) {
    if (elements->is_the_hole(isolate_, i)) {
      EnsureCapacity(5);
      SeparatorUnchecked(i > 0);
      AppendCStringLiteralUnchecked("null");
      return SUCCESS;
    }
#ifdef V8_ENABLE_UNDEFINED_DOUBLE
    if constexpr (IsDoubleElementsKind(kind)) {
      if (elements->is_undefined(i)) {
        EnsureCapacity(5);
        SeparatorUnchecked(i > 0);
        AppendCStringLiteralUnchecked("null");
        return SUCCESS;
      }
    }
#endif  // V8_ENABLE_UNDEFINED_DOUBLE
  }
  DCHECK(!elements->is_the_hole(isolate_, i));
  Separator(i > 0);
  if constexpr (IsSmiElementsKind(kind)) {
    SerializeSmi(Cast<Smi>(elements->get(i)));
  } else if constexpr (IsDoubleElementsKind(kind)) {
    SerializeDouble(elements->get_scalar(i));
  } else {
    Tagged<JSAny> obj = Cast<JSAny>(elements->get(i));
    DisableGCMole no_gc_mole;
    FastRdnStringifierResult result;
    V8_INLINE_STATEMENT result = TrySerializeSimpleObject(obj);
    switch (result) {
      case UNDEFINED:
        AppendCStringLiteral("null");
        return SUCCESS;
      case CHANGE_ENCODING:
        if constexpr (is_one_byte) {
          DCHECK(IsString(obj));
          stack_.push_back(
              RdnContinuationRecord::
                  ForJSArrayResume<kind, with_interrupt_checks>(
                      elements, i + 1, length));
          stack_.push_back(RdnContinuationRecord::ForSimpleObject(obj));
          return result;
        } else {
          UNREACHABLE();
        }
      case JS_OBJECT:
      case JS_ARRAY:
        stack_.push_back(
            RdnContinuationRecord::
                ForJSArrayResume<kind, with_interrupt_checks>(
                    elements, i + 1, length));
        stack_.push_back(RdnContinuationRecord::ForJSAny(obj, result));
        return result;
      case SUCCESS:
      case SLOW_PATH:
      case EXCEPTION:
        return result;
    }
    UNREACHABLE();
  }
  return SUCCESS;
}

// ── Interrupt + cycle detection ──

template <typename Char>
FastRdnStringifierResult
FastRdnStringifier<Char>::HandleInterruptAndCheckCycle() {
  StackLimitCheck interrupt_check(isolate_);
  {
    AllowGarbageCollection allow_gc;
    if (V8_UNLIKELY(interrupt_check.InterruptRequested() &&
                    IsExceptionHole(isolate_->stack_guard()->HandleInterrupts(
                                        StackGuard::InterruptLevel::kNoGC),
                                    isolate_))) {
      return EXCEPTION;
    }
  }
  if (V8_UNLIKELY(CheckCycle())) {
    return SLOW_PATH;
  }
  return SUCCESS;
}

template <typename Char>
bool FastRdnStringifier<Char>::CheckCycle() {
  std::unordered_set<Address> set;
  for (uint32_t i = 0; i < stack_.size(); i++) {
    RdnContinuationRecord rec = stack_[i];
    if (rec.type() == RdnContinuationRecord::kObjectKey ||
        rec.type() == RdnContinuationRecord::kSimpleObject)
      continue;
    Tagged<Object> obj = rec.object();
    if (V8_UNLIKELY(set.find(obj.ptr()) != set.end())) {
      return true;
    }
    set.insert(obj.ptr());
  }
  return false;
}

// ── Main entry + continuation loop ──

template <typename Char>
FastRdnStringifierResult FastRdnStringifier<Char>::SerializeObject(
    Tagged<JSAny> object, const DisallowGarbageCollection& no_gc) {
  // RDN: No toJSON checks. Only cache prototypes for cross-context safety.
  if (!object.IsSmi() && (IsJSObject(object) || IsJSArray(object))) {
    Tagged<HeapObject> obj = Cast<HeapObject>(object);
    Tagged<Map> meta_map = obj->map()->map();
    if (V8_UNLIKELY(meta_map == ReadOnlyRoots(isolate_).meta_map())) {
      return SLOW_PATH;
    }
    Tagged<NativeContext> native_context = meta_map->native_context();
    initial_jsobject_proto_ = native_context->initial_object_prototype();
    initial_jsarray_proto_ = native_context->initial_array_prototype();
    Tagged<HeapObject> jsarray_proto_proto =
        initial_jsarray_proto_->map()->prototype();
    if (V8_UNLIKELY(jsarray_proto_proto != initial_jsobject_proto_)) {
      return SLOW_PATH;
    }
  }
  DisableGCMole no_gc_mole;
  FastRdnStringifierResult result = TrySerializeSimpleObject(object);
  if constexpr (is_one_byte) {
    if (V8_UNLIKELY(result == CHANGE_ENCODING)) {
      DCHECK(IsString(object));
      stack_.push_back(RdnContinuationRecord::ForSimpleObject(object));
      return result;
    }
  } else {
    DCHECK_NE(result, CHANGE_ENCODING);
  }
  if (result != JS_OBJECT && result != JS_ARRAY) {
    return result;
  }
  return SerializeObject(RdnContinuationRecord::ForJSAny(object, result),
                         no_gc);
}

template <typename Char>
FastRdnStringifierResult FastRdnStringifier<Char>::SerializeObject(
    RdnContinuationRecord cont, const DisallowGarbageCollection& no_gc) {
  DisableGCMole no_gc_mole;
  uint32_t interrupt_budget = kGlobalInterruptBudget;
  FastRdnStringifierResult result;
  while (true) {
    --interrupt_budget;
    if (V8_UNLIKELY(interrupt_budget == 0)) {
      result = HandleInterruptAndCheckCycle();
      if (V8_UNLIKELY(result != SUCCESS)) return result;
      interrupt_budget = kGlobalInterruptBudget;
    }
    switch (cont.type()) {
      case RdnContinuationRecord::kObject:
        result = SerializeJSObject(cont.js_object(), no_gc);
        break;
      case RdnContinuationRecord::kObjectResume_Uninitialized:
        result = ResumeJSObject<FastIterableState::kUnknown>(
            cont.js_object(), cont.object_descriptor_idx(),
            cont.object_nof_descriptors(), cont.object_in_object_properties(),
            cont.object_in_object_properties_start(),
            cont.object_descriptors(), true, no_gc);
        break;
      case RdnContinuationRecord::kObjectResume_FastIterable:
        result = ResumeJSObject<FastIterableState::kJsonFast>(
            cont.js_object(), cont.object_descriptor_idx(),
            cont.object_nof_descriptors(), cont.object_in_object_properties(),
            cont.object_in_object_properties_start(),
            cont.object_descriptors(), true, no_gc);
        break;
      case RdnContinuationRecord::kObjectResume_SlowIterable:
        result = ResumeJSObject<FastIterableState::kJsonSlow>(
            cont.js_object(), cont.object_descriptor_idx(),
            cont.object_nof_descriptors(), cont.object_in_object_properties(),
            cont.object_in_object_properties_start(),
            cont.object_descriptors(), true, no_gc);
        break;
      case RdnContinuationRecord::kArray:
        result = SerializeJSArray(cont.js_array());
        break;
      case RdnContinuationRecord::kArrayResume:
        result = SerializeFixedArray<PACKED_ELEMENTS>(
            cont.array_elements(), cont.array_index(), cont.array_length());
        break;
      case RdnContinuationRecord::kArrayResume_Holey:
        result = SerializeFixedArray<HOLEY_ELEMENTS>(
            cont.array_elements(), cont.array_index(), cont.array_length());
        break;
      case RdnContinuationRecord::kArrayResume_WithInterrupts:
        result = SerializeFixedArrayWithInterruptCheck<PACKED_ELEMENTS>(
            cont.array_elements(), cont.array_index(), cont.array_length());
        break;
      case RdnContinuationRecord::kArrayResume_Holey_WithInterrupts:
        result = SerializeFixedArrayWithInterruptCheck<HOLEY_ELEMENTS>(
            cont.array_elements(), cont.array_index(), cont.array_length());
        break;
      default:
        UNREACHABLE();
    }
    static_assert(SUCCESS == 0);
    static_assert(JS_OBJECT == 1);
    static_assert(JS_ARRAY == 2);
    if (V8_UNLIKELY(result > JS_ARRAY)) return result;
    if (stack_.empty()) return SUCCESS;
    cont = stack_.back();
    stack_.pop_back();
  }
}

// ── ResumeFrom (encoding transition) ──

template <typename Char>
template <typename OldChar>
  requires(sizeof(OldChar) < sizeof(Char))
FastRdnStringifierResult FastRdnStringifier<Char>::ResumeFrom(
    FastRdnStringifier<OldChar>& old_stringifier,
    const DisallowGarbageCollection& no_gc) {
  DCHECK_EQ(ResultLength(), 0);
  DCHECK(stack_.empty());
  DCHECK(!old_stringifier.stack_.empty());
  initial_jsobject_proto_ = old_stringifier.initial_jsobject_proto_;
  initial_jsarray_proto_ = old_stringifier.initial_jsarray_proto_;
  stack_ = old_stringifier.stack_;
  RdnContinuationRecord cont = stack_.back();
  stack_.pop_back();
  if (cont.type() == RdnContinuationRecord::kObjectKey) {
    FastRdnStringifierObjectKeyResult key_result = SerializeObjectKey<false>(
        cont.object_key(), cont.object_key_comma(), no_gc);
    USE(key_result);
    DCHECK_NE(key_result, FastRdnStringifierObjectKeyResult::kChangeEncoding);
    DCHECK_GE(stack_.size(), 2);
    cont = stack_.back();
    stack_.pop_back();
    DCHECK(RdnContinuationRecord::IsObjectResumeType(stack_.back().type()));
  }
  if (cont.type() == RdnContinuationRecord::kSimpleObject) {
    DisableGCMole no_gc_mole;
    FastRdnStringifierResult result =
        TrySerializeSimpleObject(cont.simple_object());
    if (V8_UNLIKELY(result != SUCCESS)) {
      DCHECK_EQ(result, SLOW_PATH);
      return result;
    }
    if (stack_.empty()) return result;
    cont = stack_.back();
    stack_.pop_back();
  }
  DCHECK(cont.type() != RdnContinuationRecord::kSimpleObject &&
         cont.type() != RdnContinuationRecord::kObjectKey);
  return SerializeObject(cont, no_gc);
}

// ── FastRdnStringify wrapper ──

MaybeHandle<Object> FastRdnStringify(Isolate* isolate,
                                     Handle<Object> object) {
  if (IsUndefined(*object, isolate) || IsJSFunction(*object) ||
      IsSymbol(*object)) {
    return isolate->factory()->undefined_value();
  }
  DisallowGarbageCollection no_gc;
  FastRdnStringifier<uint8_t> one_byte(isolate);
  std::optional<FastRdnStringifier<base::uc16>> two_byte;
  FastRdnStringifierResult result =
      one_byte.SerializeObject(Cast<JSAny>(*object), no_gc);
  bool result_is_one_byte = true;
  if (result == CHANGE_ENCODING) {
    two_byte.emplace(isolate);
    result = two_byte->ResumeFrom(one_byte, no_gc);
    DCHECK_NE(result, CHANGE_ENCODING);
    result_is_one_byte = false;
  }
  if (V8_LIKELY(result == SUCCESS)) {
    if (result_is_one_byte) {
      const size_t length = one_byte.ResultLength();
      Handle<SeqOneByteString> ret;
      {
        AllowGarbageCollection allow_gc;
        if (length > String::kMaxLength) {
          THROW_NEW_ERROR(isolate, NewInvalidStringLengthError());
        }
        ASSIGN_RETURN_ON_EXCEPTION(
            isolate, ret,
            isolate->factory()->NewRawOneByteString(
                static_cast<int>(length)));
      }
      one_byte.CopyResultTo(ret->GetChars(no_gc));
      return ret;
    } else {
      DCHECK(two_byte.has_value());
      const size_t one_byte_len = one_byte.ResultLength();
      const size_t two_byte_len = two_byte->ResultLength();
      const size_t total = one_byte_len + two_byte_len;
      Handle<SeqTwoByteString> ret;
      {
        AllowGarbageCollection allow_gc;
        if (total > String::kMaxLength) {
          THROW_NEW_ERROR(isolate, NewInvalidStringLengthError());
        }
        ASSIGN_RETURN_ON_EXCEPTION(
            isolate, ret,
            isolate->factory()->NewRawTwoByteString(
                static_cast<int>(total)));
      }
      base::uc16* chars = ret->GetChars(no_gc);
      if (one_byte_len > 0) one_byte.CopyResultTo(chars);
      DCHECK_GT(two_byte_len, 0);
      two_byte->CopyResultTo(chars + one_byte_len);
      return ret;
    }
  } else if (result == UNDEFINED) {
    return isolate->factory()->undefined_value();
  } else if (result == SLOW_PATH) {
    AllowGarbageCollection allow_gc;
    RdnStringifier stringifier(isolate);
    return stringifier.Stringify(object);
  }
  DCHECK(result == EXCEPTION);
  CHECK(isolate->has_exception());
  return MaybeHandle<Object>();
}

}  // namespace

// ── Public entry point ────────────────────────────────────────────

MaybeHandle<Object> RdnStringify(Isolate* isolate, Handle<Object> object) {
  if (v8_flags.rdn_stringify_fast_path) {
    return FastRdnStringify(isolate, object);
  }
  RdnStringifier stringifier(isolate);
  return stringifier.Stringify(object);
}

}  // namespace internal
}  // namespace v8
