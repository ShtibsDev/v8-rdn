// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Flags: --expose-gc

// ── Basic JSON-compatible types ─────────────────────────────────────

// Primitives
assertEquals(null, RDN.parse("null"));
assertEquals(true, RDN.parse("true"));
assertEquals(false, RDN.parse("false"));
assertEquals(42, RDN.parse("42"));
assertEquals(-7, RDN.parse("-7"));
assertEquals(3.14, RDN.parse("3.14"));
assertEquals("hello", RDN.parse('"hello"'));
assertEquals("", RDN.parse('""'));

// Strings with escapes
assertEquals("a\"b", RDN.parse('"a\\"b"'));
assertEquals("a\\b", RDN.parse('"a\\\\b"'));
assertEquals("a\nb", RDN.parse('"a\\nb"'));
assertEquals("a\tb", RDN.parse('"a\\tb"'));

// Objects
assertEquals({}, RDN.parse("{}"));
assertEquals({a: 1}, RDN.parse('{"a": 1}'));
assertEquals({a: 1, b: "two", c: true}, RDN.parse('{"a": 1, "b": "two", "c": true}'));

// Arrays
assertEquals([], RDN.parse("[]"));
assertEquals([1, 2, 3], RDN.parse("[1, 2, 3]"));
assertEquals([1, "two", true, null], RDN.parse('[1, "two", true, null]'));

// Nested
assertEquals({a: [1, 2]}, RDN.parse('{"a": [1, 2]}'));
assertEquals([{x: 1}, {x: 2}], RDN.parse('[{"x": 1}, {"x": 2}]'));

// NaN, Infinity
assertTrue(isNaN(RDN.parse("NaN")));
assertEquals(Infinity, RDN.parse("Infinity"));
assertEquals(-Infinity, RDN.parse("-Infinity"));

// ── BigInt ──────────────────────────────────────────────────────────

assertEquals(42n, RDN.parse("42n"));
assertEquals(0n, RDN.parse("0n"));
assertEquals(-1n, RDN.parse("-1n"));
assertEquals(999999999999999999n, RDN.parse("999999999999999999n"));
assertEquals(123456789012345678901234567890n,
             RDN.parse("123456789012345678901234567890n"));

// ── DateTime (P1 optimized) ─────────────────────────────────────────

// Full ISO (24 chars) — inline fast path
{
  const d = RDN.parse("@2024-01-15T10:30:00.000Z");
  assertTrue(d instanceof Date);
  assertEquals(2024, d.getUTCFullYear());
  assertEquals(0, d.getUTCMonth());  // January = 0
  assertEquals(15, d.getUTCDate());
  assertEquals(10, d.getUTCHours());
  assertEquals(30, d.getUTCMinutes());
  assertEquals(0, d.getUTCSeconds());
  assertEquals(0, d.getUTCMilliseconds());
}

// ISO without millis (20 chars) — inline fast path
{
  const d = RDN.parse("@2024-06-20T15:45:30Z");
  assertTrue(d instanceof Date);
  assertEquals(2024, d.getUTCFullYear());
  assertEquals(5, d.getUTCMonth());
  assertEquals(20, d.getUTCDate());
  assertEquals(15, d.getUTCHours());
  assertEquals(45, d.getUTCMinutes());
  assertEquals(30, d.getUTCSeconds());
}

// Date only (10 chars) — inline fast path
{
  const d = RDN.parse("@2024-01-15");
  assertTrue(d instanceof Date);
  assertEquals(2024, d.getUTCFullYear());
  assertEquals(0, d.getUTCMonth());
  assertEquals(15, d.getUTCDate());
  assertEquals(0, d.getUTCHours());
}

// Unix timestamp (seconds)
{
  const d = RDN.parse("@1705312200");
  assertTrue(d instanceof Date);
  assertEquals(1705312200000, d.getTime());
}

// Unix timestamp (milliseconds)
{
  const d = RDN.parse("@1705312200000");
  assertTrue(d instanceof Date);
  assertEquals(1705312200000, d.getTime());
}

// Epoch zero
{
  const d = RDN.parse("@1970-01-01T00:00:00.000Z");
  assertEquals(0, d.getTime());
}

// Milliseconds precision
{
  const d = RDN.parse("@2024-01-15T10:30:00.123Z");
  assertEquals(123, d.getUTCMilliseconds());
}

// ── TimeOnly (P5 optimized) ─────────────────────────────────────────

{
  const t = RDN.parse("@14:30:00.500");
  assertEquals(14, t.hours);
  assertEquals(30, t.minutes);
  assertEquals(0, t.seconds);
  assertEquals(500, t.milliseconds);
}

{
  const t = RDN.parse("@00:00:00");
  assertEquals(0, t.hours);
  assertEquals(0, t.minutes);
  assertEquals(0, t.seconds);
  assertEquals(0, t.milliseconds);
}

{
  const t = RDN.parse("@23:59:59.999");
  assertEquals(23, t.hours);
  assertEquals(59, t.minutes);
  assertEquals(59, t.seconds);
  assertEquals(999, t.milliseconds);
}

// ── TimeOnly cached map: multiple TimeOnly values ───────────────────
// This tests P5 cached map construction — second+ calls use the fast path
// with FieldIndex from the type_map_cache_ FixedArray.
{
  const times = RDN.parse('[' +
    '@00:00:00,' +
    '@12:30:00,' +
    '@14:30:00.500,' +
    '@23:59:59.999' +
  ']');
  assertEquals(4, times.length);
  assertEquals(0, times[0].hours);
  assertEquals(12, times[1].hours);
  assertEquals(30, times[1].minutes);
  assertEquals(14, times[2].hours);
  assertEquals(500, times[2].milliseconds);
  assertEquals(23, times[3].hours);
  assertEquals(999, times[3].milliseconds);
}

// ── Duration (P5 optimized) ─────────────────────────────────────────

{
  const dur = RDN.parse("@P1Y2M3DT4H5M6S");
  assertEquals("P1Y2M3DT4H5M6S", dur.iso);
}

{
  const dur = RDN.parse("@PT0H0M0S");
  assertEquals("PT0H0M0S", dur.iso);
}

// Multiple durations (tests cached map fast path)
{
  const durs = RDN.parse('[@P1D, @PT1H, @P1Y2M3D]');
  assertEquals(3, durs.length);
  assertEquals("P1D", durs[0].iso);
  assertEquals("PT1H", durs[1].iso);
  assertEquals("P1Y2M3D", durs[2].iso);
}

// ── RegExp (P2 optimized) ───────────────────────────────────────────

{
  const r = RDN.parse("/^[a-z]+$/i");
  assertTrue(r instanceof RegExp);
  assertEquals("^[a-z]+$", r.source);
  assertEquals(true, r.ignoreCase);
  assertEquals(false, r.global);
}

{
  const r = RDN.parse("/test/gi");
  assertTrue(r instanceof RegExp);
  assertEquals("test", r.source);
  assertEquals(true, r.global);
  assertEquals(true, r.ignoreCase);
}

// Regex with escapes
{
  const r = RDN.parse('/^https?:\\/\\/[\\w.-]+\\.[a-z]{2,}\\/?$/gi');
  assertTrue(r instanceof RegExp);
  assertEquals(true, r.global);
  assertEquals(true, r.ignoreCase);
}

// Simple regex (no escape — zero-copy path)
{
  const r = RDN.parse("/abc/");
  assertTrue(r instanceof RegExp);
  assertEquals("abc", r.source);
}

// ── Binary base64 (P3 optimized) ────────────────────────────────────

{
  const arr = RDN.parse('b"SGVsbG8="');
  assertTrue(arr instanceof Uint8Array);
  assertEquals(5, arr.length);
  // "Hello" = [72, 101, 108, 108, 111]
  assertEquals(72, arr[0]);
  assertEquals(101, arr[1]);
  assertEquals(108, arr[2]);
  assertEquals(108, arr[3]);
  assertEquals(111, arr[4]);
}

// Empty base64
{
  const arr = RDN.parse('b""');
  assertTrue(arr instanceof Uint8Array);
  assertEquals(0, arr.length);
}

// Base64 with padding
{
  const arr = RDN.parse('b"AQID"');  // [1, 2, 3]
  assertEquals(3, arr.length);
  assertEquals(1, arr[0]);
  assertEquals(2, arr[1]);
  assertEquals(3, arr[2]);
}

// ── Binary hex (P4 optimized) ───────────────────────────────────────

{
  const arr = RDN.parse('x"48656c6c6f"');
  assertTrue(arr instanceof Uint8Array);
  assertEquals(5, arr.length);
  // "Hello" = [0x48, 0x65, 0x6c, 0x6c, 0x6f]
  assertEquals(0x48, arr[0]);
  assertEquals(0x65, arr[1]);
  assertEquals(0x6c, arr[2]);
  assertEquals(0x6c, arr[3]);
  assertEquals(0x6f, arr[4]);
}

// Empty hex
{
  const arr = RDN.parse('x""');
  assertTrue(arr instanceof Uint8Array);
  assertEquals(0, arr.length);
}

// Hex uppercase
{
  const arr = RDN.parse('x"FF00AB"');
  assertEquals(3, arr.length);
  assertEquals(0xFF, arr[0]);
  assertEquals(0x00, arr[1]);
  assertEquals(0xAB, arr[2]);
}

// ── Map (P6) ────────────────────────────────────────────────────────

{
  const m = RDN.parse('Map{}');
  assertTrue(m instanceof Map);
  assertEquals(0, m.size);
}

{
  const m = RDN.parse('Map{"a" => 1, "b" => 2, "c" => 3}');
  assertTrue(m instanceof Map);
  assertEquals(3, m.size);
  assertEquals(1, m.get("a"));
  assertEquals(2, m.get("b"));
  assertEquals(3, m.get("c"));
}

// Map with various value types
{
  const m = RDN.parse('Map{"num" => 42, "str" => "hello", "bool" => true, "null" => null}');
  assertEquals(42, m.get("num"));
  assertEquals("hello", m.get("str"));
  assertEquals(true, m.get("bool"));
  assertEquals(null, m.get("null"));
}

// ── Set (P6) ────────────────────────────────────────────────────────

{
  const s = RDN.parse('Set{}');
  assertTrue(s instanceof Set);
  assertEquals(0, s.size);
}

{
  const s = RDN.parse('Set{1, 2, 3, 4, 5}');
  assertTrue(s instanceof Set);
  assertEquals(5, s.size);
  assertTrue(s.has(1));
  assertTrue(s.has(5));
}

// Set with strings
{
  const s = RDN.parse('Set{"hello", "world"}');
  assertTrue(s instanceof Set);
  assertEquals(2, s.size);
  assertTrue(s.has("hello"));
  assertTrue(s.has("world"));
}

// ── Brace-disambiguated sets (the crash path) ───────────────────────
// This is the {value, value} syntax that ParseBrace disambiguates as Set.

{
  const s = RDN.parse('{"a", "b", "c"}');
  assertTrue(s instanceof Set);
  assertEquals(3, s.size);
  assertTrue(s.has("a"));
  assertTrue(s.has("b"));
  assertTrue(s.has("c"));
}

// Single-element set
{
  const s = RDN.parse('{"only"}');
  assertTrue(s instanceof Set);
  assertEquals(1, s.size);
  assertTrue(s.has("only"));
}

// Brace-disambiguated map
{
  const m = RDN.parse('{"key" => "value"}');
  assertTrue(m instanceof Map);
  assertEquals(1, m.size);
  assertEquals("value", m.get("key"));
}

// ── Tuple ───────────────────────────────────────────────────────────

{
  const t = RDN.parse("(1, 2, 3)");
  assertTrue(Array.isArray(t));
  assertEquals(3, t.length);
  assertEquals(1, t[0]);
  assertEquals(2, t[1]);
  assertEquals(3, t[2]);
  // Tuples are represented as regular arrays in V8
}

// ── Nested objects with RDN types ───────────────────────────────────
// Tests that cached maps survive nested HandleScope closes.

{
  const obj = RDN.parse('{"times": [@00:00:00, @12:30:00, @23:59:59], "durations": [@P1D, @PT1H]}');
  assertEquals(3, obj.times.length);
  assertEquals(0, obj.times[0].hours);
  assertEquals(12, obj.times[1].hours);
  assertEquals(23, obj.times[2].hours);
  assertEquals(2, obj.durations.length);
  assertEquals("P1D", obj.durations[0].iso);
  assertEquals("PT1H", obj.durations[1].iso);
}

// ── Deep nesting with mixed types (stress HandleScope) ──────────────
// Exercises the GC-traced FixedArray map cache with objects nested inside
// arrays inside objects — the pattern that caused the original crash.

{
  const rdn = '{"records": [' +
    '{"id": 1, "login": @14:30:00, "session": @PT1H, "tags": {"admin", "user"}, "meta": {"key" => "val"}},' +
    '{"id": 2, "login": @09:00:00, "session": @PT2H, "tags": {"editor"}, "meta": {"k2" => "v2"}},' +
    '{"id": 3, "login": @23:59:59.999, "session": @P1D, "tags": {"viewer", "guest"}, "meta": {"k3" => "v3"}}' +
  ']}';
  const result = RDN.parse(rdn);
  assertEquals(3, result.records.length);

  // Record 1
  assertEquals(1, result.records[0].id);
  assertEquals(14, result.records[0].login.hours);
  assertEquals("PT1H", result.records[0].session.iso);
  assertTrue(result.records[0].tags instanceof Set);
  assertEquals(2, result.records[0].tags.size);
  assertTrue(result.records[0].tags.has("admin"));
  assertTrue(result.records[0].meta instanceof Map);
  assertEquals("val", result.records[0].meta.get("key"));

  // Record 3 — tests cached map fast path (3rd call)
  assertEquals(3, result.records[2].id);
  assertEquals(23, result.records[2].login.hours);
  assertEquals(999, result.records[2].login.milliseconds);
  assertEquals("P1D", result.records[2].session.iso);
}

// ── GC stress test for TimeOnly/Duration cached maps ────────────────
// Forces GC between parse calls to verify the FixedArray-based cache
// survives garbage collection (the original crash was dangling Handle<Map>).

{
  // Parse first to populate cache
  RDN.parse("@10:00:00");
  RDN.parse("@PT1H");

  // Force GC
  gc();

  // Parse again — uses cached map from FixedArray (GC-safe)
  const t = RDN.parse("@12:00:00");
  assertEquals(12, t.hours);
  assertEquals(0, t.minutes);

  const d = RDN.parse("@P1Y");
  assertEquals("P1Y", d.iso);
}

// ── Large array of TimeOnly (stress FieldIndex caching) ─────────────
{
  let items = [];
  for (let i = 0; i < 100; i++) {
    items.push(`@${String(i % 24).padStart(2, '0')}:${String(i % 60).padStart(2, '0')}:00`);
  }
  const arr = RDN.parse('[' + items.join(',') + ']');
  assertEquals(100, arr.length);
  assertEquals(0, arr[0].hours);
  assertEquals(1, arr[1].hours);
  assertEquals(23, arr[23].hours);
  assertEquals(0, arr[24].hours);  // wraps around
  // Verify all have correct structure
  for (let i = 0; i < 100; i++) {
    assertEquals(i % 24, arr[i].hours);
    assertEquals(i % 60, arr[i].minutes);
    assertEquals(0, arr[i].seconds);
    assertEquals(0, arr[i].milliseconds);
  }
}

// ── Large array of Duration (stress FieldIndex caching) ─────────────
{
  let items = [];
  for (let i = 0; i < 50; i++) {
    items.push(`@P${i}D`);
  }
  const arr = RDN.parse('[' + items.join(',') + ']');
  assertEquals(50, arr.length);
  for (let i = 0; i < 50; i++) {
    assertEquals(`P${i}D`, arr[i].iso);
  }
}

// ── Stringify roundtrip tests ───────────────────────────────────────

// Date roundtrip
{
  const d = new Date("2024-01-15T10:30:00.000Z");
  const s = RDN.stringify(d);
  assertEquals("@2024-01-15T10:30:00.000Z", s);
  const d2 = RDN.parse(s);
  assertEquals(d.getTime(), d2.getTime());
}

// BigInt roundtrip
{
  assertEquals("42n", RDN.stringify(42n));
  assertEquals(42n, RDN.parse(RDN.stringify(42n)));
  assertEquals(999999999999999999n, RDN.parse(RDN.stringify(999999999999999999n)));
}

// RegExp stringify
{
  const r = /^test$/gi;
  const s = RDN.stringify(r);
  // Stringifier wraps pattern in quotes: /"^test$"/gi
  assertTrue(s.startsWith('/'));
  assertTrue(s.endsWith('/gi'));
}

// RegExp parse → stringify → parse consistency
{
  const r = RDN.parse("/^[a-z]+$/i");
  const s = RDN.stringify(r);
  // Should contain the pattern and flag
  assertTrue(s.includes("[a-z]+"));
  assertTrue(s.endsWith("/i"));
}

// Map roundtrip
{
  const m = new Map([["a", 1], ["b", 2]]);
  const s = RDN.stringify(m);
  const m2 = RDN.parse(s);
  assertTrue(m2 instanceof Map);
  assertEquals(2, m2.size);
  assertEquals(1, m2.get("a"));
  assertEquals(2, m2.get("b"));
}

// Set roundtrip
{
  const s = new Set([1, 2, 3]);
  const str = RDN.stringify(s);
  const s2 = RDN.parse(str);
  assertTrue(s2 instanceof Set);
  assertEquals(3, s2.size);
  assertTrue(s2.has(1));
  assertTrue(s2.has(2));
  assertTrue(s2.has(3));
}

// Object with mixed types roundtrip
{
  const obj = {
    id: 42,
    name: "test",
    active: true,
    created: new Date("2024-01-15T10:30:00.000Z"),
    tags: ["a", "b"],
    score: 3.14,
  };
  const s = RDN.stringify(obj);
  const obj2 = RDN.parse(s);
  assertEquals(42, obj2.id);
  assertEquals("test", obj2.name);
  assertEquals(true, obj2.active);
  assertTrue(obj2.created instanceof Date);
  assertEquals(obj.created.getTime(), obj2.created.getTime());
  assertEquals(2, obj2.tags.length);
  assertEquals(3.14, obj2.score);
}

// ── Unicode string handling (two-byte parser path) ──────────────────

{
  const obj = RDN.parse('{"name": "Hello 世界 🚀"}');
  assertEquals("Hello 世界 🚀", obj.name);
}

{
  const obj = RDN.parse('{"key": "éèê", "val": 42}');
  assertEquals("éèê", obj.key);
  assertEquals(42, obj.val);
}

// Unicode with RDN types — tests two-byte parser with Set/Map/TimeOnly
{
  const obj = RDN.parse('{"名前": "テスト", "time": @14:30:00, "tags": {"日本語", "English"}}');
  assertEquals("テスト", obj["名前"]);
  assertEquals(14, obj.time.hours);
  assertTrue(obj.tags instanceof Set);
  assertTrue(obj.tags.has("日本語"));
  assertTrue(obj.tags.has("English"));
}

// ── Stringify error cases ───────────────────────────────────────────

// Parse errors
assertThrows(() => RDN.parse(""), SyntaxError);
assertThrows(() => RDN.parse("{"), SyntaxError);
assertThrows(() => RDN.parse("[1,"), SyntaxError);
// Note: '{"key"}' is valid RDN — it's a single-element Set
assertThrows(() => RDN.parse('{"key":'), SyntaxError);

// ── Monomorphic object arrays (tests map cache) ─────────────────────

{
  const arr = RDN.parse('[' +
    '{"x": 1, "y": 2},' +
    '{"x": 3, "y": 4},' +
    '{"x": 5, "y": 6},' +
    '{"x": 7, "y": 8},' +
    '{"x": 9, "y": 10}' +
  ']');
  assertEquals(5, arr.length);
  for (let i = 0; i < 5; i++) {
    assertEquals(i * 2 + 1, arr[i].x);
    assertEquals(i * 2 + 2, arr[i].y);
  }
}

// ── Holey arrays (S4 optimization) ──────────────────────────────────

{
  const arr = [1, , 3, , 5];
  const s = RDN.stringify(arr);
  const arr2 = RDN.parse(s);
  assertEquals(5, arr2.length);
  assertEquals(1, arr2[0]);
  assertEquals(null, arr2[1]);
  assertEquals(3, arr2[2]);
  assertEquals(null, arr2[3]);
  assertEquals(5, arr2[4]);
}
