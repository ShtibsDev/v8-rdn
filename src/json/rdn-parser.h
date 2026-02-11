// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_JSON_RDN_PARSER_H_
#define V8_JSON_RDN_PARSER_H_

#include "src/base/small-vector.h"
#include "src/base/strings.h"
#include "src/execution/isolate.h"
#include "src/heap/factory.h"
#include "src/objects/objects.h"
#include "src/objects/string.h"

namespace v8 {
namespace internal {

// Deferred string descriptor — records location in source without allocation.
// Modeled after JsonString in json-parser.h.
class RdnString final {
 public:
  RdnString()
      : start_(0),
        length_(0),
        needs_conversion_(false),
        internalize_(false),
        has_escape_(false) {}

  RdnString(uint32_t start, uint32_t length, bool needs_conversion,
            bool internalize, bool has_escape)
      : start_(start),
        length_(length),
        needs_conversion_(needs_conversion),
        internalize_(internalize),
        has_escape_(has_escape) {}

  bool internalize() const { return internalize_; }
  bool needs_conversion() const { return needs_conversion_; }
  bool has_escape() const { return has_escape_; }
  uint32_t start() const { return start_; }
  uint32_t length() const { return length_; }

 private:
  uint32_t start_;
  uint32_t length_;
  bool needs_conversion_ : 1;
  bool internalize_ : 1;
  bool has_escape_ : 1;
};

// Property descriptor for deferred object construction via RdnDataObjectBuilder.
// Holds the raw RdnString key (position + length, no allocation) alongside the
// parsed value. This enables the builder's iterator to call GetKeyChars()
// without materializing strings.
struct RdnProperty {
  RdnProperty() = default;
  RdnProperty(const RdnString& string, Handle<Object> value)
      : string(string), value(value) {}
  // Constructor for pre-materialized keys (rare paths: deprecated map, slow
  // ParseBrace). The materialized_key is returned by the iterator's GetKey()
  // while the dummy RdnString causes the builder's fast transition to skip.
  RdnProperty(Handle<String> materialized_key, Handle<Object> value)
      : string(), value(value), materialized_key(materialized_key) {}
  RdnString string;
  Handle<Object> value;
  Handle<String> materialized_key;
};

// RDN parser — recursive descent parser for the RDN data format.
// Template on Char (uint8_t for one-byte strings, uint16_t for two-byte).
template <typename Char>
class RdnParser final {
 public:
  using SeqString = typename CharTraits<Char>::String;
  using SeqExternalString = typename CharTraits<Char>::ExternalString;

  V8_WARN_UNUSED_RESULT static MaybeHandle<Object> Parse(
      Isolate* isolate, Handle<String> source);

  static constexpr base::uc32 kEndOfString = static_cast<base::uc32>(-1);
  static constexpr base::uc32 kInvalidUnicodeCharacter =
      static_cast<base::uc32>(-1);

  // Nested iterator class — implemented in rdn-parser.cc.
  class RdnNamedPropertyIterator;

 private:
  RdnParser(Isolate* isolate, Handle<String> source);
  ~RdnParser();

  MaybeHandle<Object> ParseRdn();
  // Inline hot path: dispatches to the 7 common JSON types without function
  // call overhead. Falls through to ParseValueSlow for RDN-specific types.
  V8_INLINE MaybeHandle<Object> ParseValue();
  MaybeHandle<Object> ParseValueSlow();
  MaybeHandle<Object> ParseString();
  MaybeHandle<Object> ParseNumber();
  // Raw number parsing for array fast path. Returns true if result is a double
  // (stored in *result_double), false if result is a Smi (stored in
  // *result_smi). Sets *is_fallback to true if the number cannot be parsed as
  // a simple numeric (BigInt suffix, -Infinity, etc.) — caller should use
  // ParseNumber() instead. On fallback, cursor is restored to before the number.
  bool ParseNumberRaw(double* result_double, int* result_smi, bool* is_fallback);
  MaybeHandle<Object> ParseArray();
  MaybeHandle<Object> ParseTuple();
  MaybeHandle<Object> ParseBrace();
  // Fast path: first key as deferred RdnString descriptor (from ParseBrace
  // string path). Uses property_stack_ + RdnDataObjectBuilder for optimal
  // object construction with deferred string materialization.
  MaybeHandle<Object> FinishObject(const RdnString& first_key_desc,
                                   Handle<Map> feedback = Handle<Map>());
  // Slow path: first key already materialized (rare paths: ParseBrace slow
  // disambiguation, deprecated map fallback). Uses simple AddProperty loop.
  MaybeHandle<Object> FinishObjectMaterialized(Handle<String> first_key);
  MaybeHandle<Object> FinishObjectFastKeys(Handle<Map> feedback,
                                           Handle<DescriptorArray> descriptors,
                                           int nof_descriptors);
  MaybeHandle<Object> FinishMap(Handle<Object> first_key);
  MaybeHandle<Object> FinishSet(Handle<Object> first_value);
  MaybeHandle<Object> ParseMapKeyword();
  MaybeHandle<Object> ParseSetKeyword();
  MaybeHandle<Object> ParseDateTime();
  MaybeHandle<Object> ParseDuration();
  MaybeHandle<Object> ParseRegex();
  MaybeHandle<Object> ParseBinaryB64();
  MaybeHandle<Object> ParseBinaryHex();

  MaybeHandle<Object> MakeDate(double time_ms);
  MaybeHandle<Object> MakeTimeOnly(int h, int m, int s, int ms);
  MaybeHandle<Object> MakeDuration(Handle<String> iso);

  // Deferred string scanning — scans string content without allocating.
  // Must be called after the opening '"' has been consumed.
  // Returns a descriptor; call MakeString() to materialize.
  RdnString ScanRdnString(bool needs_internalization);
  Handle<String> MakeString(const RdnString& string,
                            Handle<String> hint = Handle<String>());
  base::Vector<const Char> GetKeyChars(const RdnString& key) {
    return base::Vector<const Char>(chars_ + key.start(), key.length());
  }

  template <typename SinkChar>
  void DecodeString(SinkChar* sink, uint32_t start, uint32_t length);

  template <typename SinkSeqString>
  Handle<String> DecodeString(const RdnString& string,
                              Handle<SinkSeqString> intermediate,
                              Handle<String> hint);

  base::uc32 ScanUnicodeCharacter();

  V8_INLINE void SkipWhitespace() {
    while (cursor_ < end_) {
      Char c = *cursor_;
      if (c != ' ' && c != '\n' && c != '\r' && c != '\t') break;
      cursor_++;
    }
  }

  V8_INLINE base::uc32 CurrentChar() const {
    if (V8_UNLIKELY(cursor_ >= end_)) return kEndOfString;
    return *cursor_;
  }

  Char Peek(int offset = 0) const {
    const Char* p = cursor_ + offset;
    if (p >= end_) return 0;
    return *p;
  }

  V8_INLINE void Advance(int n = 1) { cursor_ += n; }

  V8_INLINE bool IsAtEnd() const { return cursor_ >= end_; }

  V8_INLINE bool Match(const char* str, int len) {
    if (end_ - cursor_ < len) return false;
    for (int i = 0; i < len; i++) {
      if (cursor_[i] != static_cast<Char>(str[i])) return false;
    }
    return true;
  }

  V8_INLINE uint32_t position() const {
    return static_cast<uint32_t>(cursor_ - chars_);
  }

  V8_INLINE size_t remaining_chars() const { return end_ - cursor_; }

  // Compare raw cursor bytes against expected key without materializing a
  // string. Returns true when bytes at cursor_ match key_chars and are followed
  // by a closing '"'.
  V8_INLINE bool FastKeyMatch(const uint8_t* key_chars, uint32_t key_length);

  // Overloaded ParseValue that stores feedback for the next ParseBrace.
  MaybeHandle<Object> ParseValue(Handle<Map> feedback);

  void ReportError(const char* message);

  // GC pointer relocation callback — updates raw pointers when the source
  // string is relocated during garbage collection.
  // Ported from JsonParser (json-parser.h:462-476).
  static void UpdatePointersCallback(void* parser) {
    reinterpret_cast<RdnParser<Char>*>(parser)->UpdatePointers();
  }

  void UpdatePointers() {
    DisallowGarbageCollection no_gc;
    const Char* chars = Cast<SeqString>(source_)->GetChars(no_gc);
    if (chars_ != chars) {
      size_t pos = cursor_ - chars_;
      size_t len = end_ - chars_;
      chars_ = chars;
      cursor_ = chars_ + pos;
      end_ = chars_ + len;
    }
  }

  Isolate* isolate_;
  Factory* factory_;
  Handle<String> source_;
  const Char* chars_;
  const Char* end_;
  const Char* cursor_;
  bool has_error_;
  // Whether the source string bytes can relocate during GC.
  // True for on-heap SeqStrings, false for external strings.
  bool chars_may_relocate_;

  // Multi-entry map cache: stores the final maps of recently-built objects
  // indexed by shape. When a new object has the same keys in the same order
  // as a cached entry, we skip all transition lookups and write properties
  // directly at known offsets via FastPropertyAtPut.
  // The maps are stored in a heap-allocated FixedArray for GC safety —
  // Handle<Map> members become dangling when the local HandleScope is closed
  // by CloseAndEscape, but FixedArray entries are properly traced by GC.
  static constexpr int kObjectMapCacheSize = 4;
  Handle<FixedArray> object_map_cache_;
  int object_map_cache_counts_[kObjectMapCacheSize] = {};
  int object_map_cache_next_ = 0;  // round-robin insertion index

  // Feedback from previous array element for FastKeyMatch.
  // Set by ParseValue(Handle<Map>) before calling ParseValue(), consumed by
  // ParseBrace to attempt the fast-key path.
  Handle<Map> array_element_feedback_;

  // Persistent element storage for the array number fast path.
  // Reused across calls to avoid repeated allocation.
  // Reference: json-parser.h smi_elements_ / double_elements_.
  base::SmallVector<int, 64> smi_elements_;
  base::SmallVector<double, 64> double_elements_;

  // Persistent property/element stacks for nested parsing.
  // Replaces per-call-frame SmallVector allocations.
  // Reference: json-parser.h property_stack_ / element_stack_.
  base::SmallVector<Handle<Object>, 16> element_stack_;
  base::SmallVector<RdnProperty, 16> property_stack_;

  // Cached object constructor for fast empty {} creation.
  Handle<JSFunction> object_constructor_;

  // Whether the map cache has ever been populated. Skips the 4-entry linear
  // scan in ParseBrace when all entries are empty.
  bool map_cache_populated_ = false;
};

extern template class RdnParser<uint8_t>;
extern template class RdnParser<uint16_t>;

}  // namespace internal
}  // namespace v8

#endif  // V8_JSON_RDN_PARSER_H_
