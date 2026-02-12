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

// ── Map: all types as keys and values ─────────────────────────────────
// Tests every RDN type as both map key and value, with and without
// whitespace around the arrow operator.

// Helper: for non-primitive keys we can't use Map.get() (reference equality),
// so we iterate entries and check by index.
function mapEntry(m, index) {
  let i = 0;
  for (const [k, v] of m) {
    if (i === index) return {key: k, value: v};
    i++;
  }
  throw new Error("map entry " + index + " not found");
}

// ── Primitive keys (can use .get()) ──────────────────────────────────

// null key — no space / with space
{
  const m1 = RDN.parse('Map{null=>"v1"}');
  assertEquals("v1", m1.get(null));
  const m2 = RDN.parse('Map{null => "v2"}');
  assertEquals("v2", m2.get(null));
}

// boolean keys — no space / with space
{
  const m1 = RDN.parse('Map{true=>"yes", false=>"no"}');
  assertEquals("yes", m1.get(true));
  assertEquals("no", m1.get(false));
  const m2 = RDN.parse('Map{true => "yes", false => "no"}');
  assertEquals("yes", m2.get(true));
  assertEquals("no", m2.get(false));
}

// number keys — integer, float, NaN, Infinity, -Infinity
{
  const m1 = RDN.parse('Map{42=>"int", 3.14=>"float", NaN=>"nan", Infinity=>"inf", -Infinity=>"ninf"}');
  assertEquals("int", m1.get(42));
  assertEquals("float", m1.get(3.14));
  assertEquals("inf", m1.get(Infinity));
  assertEquals("ninf", m1.get(-Infinity));
  // NaN !== NaN, so iterate
  let nanVal;
  for (const [k, v] of m1) { if (typeof k === "number" && isNaN(k)) nanVal = v; }
  assertEquals("nan", nanVal);

  const m2 = RDN.parse('Map{42 => "int", 3.14 => "float", NaN => "nan", Infinity => "inf", -Infinity => "ninf"}');
  assertEquals("int", m2.get(42));
  assertEquals("float", m2.get(3.14));
  assertEquals("inf", m2.get(Infinity));
  assertEquals("ninf", m2.get(-Infinity));
}

// string keys — no space / with space
{
  const m1 = RDN.parse('Map{"hello"=>1}');
  assertEquals(1, m1.get("hello"));
  const m2 = RDN.parse('Map{"hello" => 1}');
  assertEquals(1, m2.get("hello"));
}

// bigint keys — no space / with space
{
  const m1 = RDN.parse('Map{42n=>"big"}');
  assertEquals("big", m1.get(42n));
  const m2 = RDN.parse('Map{42n => "big"}');
  assertEquals("big", m2.get(42n));
  const m3 = RDN.parse('Map{999999999999999999n => "huge"}');
  assertEquals("huge", m3.get(999999999999999999n));
}

// ── Non-primitive keys (use mapEntry helper) ─────────────────────────

// ── DateTime key: all format variations ──────────────────────────────

// date-only (10 chars) — no space / with space
{
  const m1 = RDN.parse('Map{@2024-01-15=>"date-only"}');
  const e1 = mapEntry(m1, 0);
  assertTrue(e1.key instanceof Date);
  assertEquals(2024, e1.key.getUTCFullYear());
  assertEquals(0, e1.key.getUTCMonth());
  assertEquals(15, e1.key.getUTCDate());
  assertEquals(0, e1.key.getUTCHours());
  assertEquals("date-only", e1.value);

  const m2 = RDN.parse('Map{@2024-01-15 => "date-only"}');
  const e2 = mapEntry(m2, 0);
  assertTrue(e2.key instanceof Date);
  assertEquals(2024, e2.key.getUTCFullYear());
  assertEquals("date-only", e2.value);
}

// full ISO (24 chars) — no space / with space
{
  const m1 = RDN.parse('Map{@2024-01-15T10:30:00.123Z=>"full-iso"}');
  const e1 = mapEntry(m1, 0);
  assertTrue(e1.key instanceof Date);
  assertEquals(2024, e1.key.getUTCFullYear());
  assertEquals(10, e1.key.getUTCHours());
  assertEquals(30, e1.key.getUTCMinutes());
  assertEquals(123, e1.key.getUTCMilliseconds());
  assertEquals("full-iso", e1.value);

  const m2 = RDN.parse('Map{@2024-01-15T10:30:00.123Z => "full-iso"}');
  const e2 = mapEntry(m2, 0);
  assertTrue(e2.key instanceof Date);
  assertEquals(10, e2.key.getUTCHours());
  assertEquals(123, e2.key.getUTCMilliseconds());
  assertEquals("full-iso", e2.value);
}

// ISO without millis (20 chars) — no space / with space
{
  const m1 = RDN.parse('Map{@2024-06-20T15:45:30Z=>"iso-no-ms"}');
  const e1 = mapEntry(m1, 0);
  assertTrue(e1.key instanceof Date);
  assertEquals(2024, e1.key.getUTCFullYear());
  assertEquals(5, e1.key.getUTCMonth());
  assertEquals(15, e1.key.getUTCHours());
  assertEquals(45, e1.key.getUTCMinutes());
  assertEquals(30, e1.key.getUTCSeconds());
  assertEquals(0, e1.key.getUTCMilliseconds());
  assertEquals("iso-no-ms", e1.value);

  const m2 = RDN.parse('Map{@2024-06-20T15:45:30Z => "iso-no-ms"}');
  const e2 = mapEntry(m2, 0);
  assertTrue(e2.key instanceof Date);
  assertEquals(15, e2.key.getUTCHours());
  assertEquals("iso-no-ms", e2.value);
}

// unix timestamp seconds — no space / with space
{
  const m1 = RDN.parse('Map{@1705312200=>"unix-sec"}');
  const e1 = mapEntry(m1, 0);
  assertTrue(e1.key instanceof Date);
  assertEquals(1705312200000, e1.key.getTime());
  assertEquals("unix-sec", e1.value);

  const m2 = RDN.parse('Map{@1705312200 => "unix-sec"}');
  const e2 = mapEntry(m2, 0);
  assertTrue(e2.key instanceof Date);
  assertEquals(1705312200000, e2.key.getTime());
  assertEquals("unix-sec", e2.value);
}

// unix timestamp milliseconds — no space / with space
{
  const m1 = RDN.parse('Map{@1705312200000=>"unix-ms"}');
  const e1 = mapEntry(m1, 0);
  assertTrue(e1.key instanceof Date);
  assertEquals(1705312200000, e1.key.getTime());
  assertEquals("unix-ms", e1.value);

  const m2 = RDN.parse('Map{@1705312200000 => "unix-ms"}');
  const e2 = mapEntry(m2, 0);
  assertTrue(e2.key instanceof Date);
  assertEquals(1705312200000, e2.key.getTime());
  assertEquals("unix-ms", e2.value);
}

// epoch zero as key
{
  const m = RDN.parse('Map{@1970-01-01T00:00:00.000Z => "epoch"}');
  const e = mapEntry(m, 0);
  assertTrue(e.key instanceof Date);
  assertEquals(0, e.key.getTime());
  assertEquals("epoch", e.value);
}

// all datetime formats as keys in one map
{
  const m = RDN.parse(
    'Map{' +
      '@2024-01-15 => "date-only", ' +
      '@2024-01-15T10:30:00.000Z => "full-iso", ' +
      '@2024-06-20T15:45:30Z => "iso-no-ms", ' +
      '@1705312200 => "unix-sec", ' +
      '@1705312200000 => "unix-ms"' +
    '}'
  );
  assertEquals(5, m.size);
  const entries = [...m];
  assertTrue(entries[0][0] instanceof Date);
  assertEquals("date-only", entries[0][1]);
  assertTrue(entries[1][0] instanceof Date);
  assertEquals("full-iso", entries[1][1]);
  assertTrue(entries[2][0] instanceof Date);
  assertEquals("iso-no-ms", entries[2][1]);
  assertTrue(entries[3][0] instanceof Date);
  assertEquals("unix-sec", entries[3][1]);
  assertTrue(entries[4][0] instanceof Date);
  assertEquals("unix-ms", entries[4][1]);
}

// all datetime formats as values — no space
{
  const m = RDN.parse(
    'Map{' +
      '"date-only"=>@2024-01-15,' +
      '"full-iso"=>@2024-01-15T10:30:00.123Z,' +
      '"iso-no-ms"=>@2024-06-20T15:45:30Z,' +
      '"unix-sec"=>@1705312200,' +
      '"unix-ms"=>@1705312200000,' +
      '"epoch"=>@1970-01-01T00:00:00.000Z' +
    '}'
  );
  assertEquals(6, m.size);
  assertTrue(m.get("date-only") instanceof Date);
  assertEquals(2024, m.get("date-only").getUTCFullYear());
  assertEquals(0, m.get("date-only").getUTCMonth());
  assertEquals(15, m.get("date-only").getUTCDate());
  assertTrue(m.get("full-iso") instanceof Date);
  assertEquals(10, m.get("full-iso").getUTCHours());
  assertEquals(123, m.get("full-iso").getUTCMilliseconds());
  assertTrue(m.get("iso-no-ms") instanceof Date);
  assertEquals(15, m.get("iso-no-ms").getUTCHours());
  assertEquals(0, m.get("iso-no-ms").getUTCMilliseconds());
  assertTrue(m.get("unix-sec") instanceof Date);
  assertEquals(1705312200000, m.get("unix-sec").getTime());
  assertTrue(m.get("unix-ms") instanceof Date);
  assertEquals(1705312200000, m.get("unix-ms").getTime());
  assertTrue(m.get("epoch") instanceof Date);
  assertEquals(0, m.get("epoch").getTime());
}

// all datetime formats as values — with space
{
  const m = RDN.parse(
    'Map{' +
      '"date-only" => @2024-01-15, ' +
      '"full-iso" => @2024-01-15T10:30:00.123Z, ' +
      '"iso-no-ms" => @2024-06-20T15:45:30Z, ' +
      '"unix-sec" => @1705312200, ' +
      '"unix-ms" => @1705312200000, ' +
      '"epoch" => @1970-01-01T00:00:00.000Z' +
    '}'
  );
  assertEquals(6, m.size);
  assertTrue(m.get("date-only") instanceof Date);
  assertEquals(2024, m.get("date-only").getUTCFullYear());
  assertTrue(m.get("full-iso") instanceof Date);
  assertEquals(123, m.get("full-iso").getUTCMilliseconds());
  assertTrue(m.get("iso-no-ms") instanceof Date);
  assertEquals(30, m.get("iso-no-ms").getUTCSeconds());
  assertTrue(m.get("unix-sec") instanceof Date);
  assertEquals(1705312200000, m.get("unix-sec").getTime());
  assertTrue(m.get("unix-ms") instanceof Date);
  assertEquals(1705312200000, m.get("unix-ms").getTime());
  assertTrue(m.get("epoch") instanceof Date);
  assertEquals(0, m.get("epoch").getTime());
}

// ── TimeOnly key: all format variations ──────────────────────────────

// without millis — no space / with space
{
  const m1 = RDN.parse('Map{@14:30:00=>"no-ms"}');
  const e1 = mapEntry(m1, 0);
  assertEquals(14, e1.key.hours);
  assertEquals(30, e1.key.minutes);
  assertEquals(0, e1.key.seconds);
  assertEquals(0, e1.key.milliseconds);
  assertEquals("no-ms", e1.value);

  const m2 = RDN.parse('Map{@14:30:00 => "no-ms"}');
  const e2 = mapEntry(m2, 0);
  assertEquals(14, e2.key.hours);
  assertEquals(0, e2.key.milliseconds);
  assertEquals("no-ms", e2.value);
}

// with millis — no space / with space
{
  const m1 = RDN.parse('Map{@14:30:00.500=>"with-ms"}');
  const e1 = mapEntry(m1, 0);
  assertEquals(14, e1.key.hours);
  assertEquals(30, e1.key.minutes);
  assertEquals(0, e1.key.seconds);
  assertEquals(500, e1.key.milliseconds);
  assertEquals("with-ms", e1.value);

  const m2 = RDN.parse('Map{@14:30:00.500 => "with-ms"}');
  const e2 = mapEntry(m2, 0);
  assertEquals(500, e2.key.milliseconds);
  assertEquals("with-ms", e2.value);
}

// midnight — no space / with space
{
  const m1 = RDN.parse('Map{@00:00:00=>"midnight"}');
  const e1 = mapEntry(m1, 0);
  assertEquals(0, e1.key.hours);
  assertEquals(0, e1.key.minutes);
  assertEquals(0, e1.key.seconds);
  assertEquals(0, e1.key.milliseconds);
  assertEquals("midnight", e1.value);

  const m2 = RDN.parse('Map{@00:00:00 => "midnight"}');
  const e2 = mapEntry(m2, 0);
  assertEquals(0, e2.key.hours);
  assertEquals("midnight", e2.value);
}

// end of day — no space / with space
{
  const m1 = RDN.parse('Map{@23:59:59.999=>"eod"}');
  const e1 = mapEntry(m1, 0);
  assertEquals(23, e1.key.hours);
  assertEquals(59, e1.key.minutes);
  assertEquals(59, e1.key.seconds);
  assertEquals(999, e1.key.milliseconds);
  assertEquals("eod", e1.value);

  const m2 = RDN.parse('Map{@23:59:59.999 => "eod"}');
  const e2 = mapEntry(m2, 0);
  assertEquals(23, e2.key.hours);
  assertEquals(999, e2.key.milliseconds);
  assertEquals("eod", e2.value);
}

// all timeonly variations as keys in one map
{
  const m = RDN.parse(
    'Map{' +
      '@00:00:00 => "midnight", ' +
      '@12:30:00 => "noon", ' +
      '@14:30:00.500 => "afternoon", ' +
      '@23:59:59.999 => "eod"' +
    '}'
  );
  assertEquals(4, m.size);
  const entries = [...m];
  assertEquals(0, entries[0][0].hours);
  assertEquals("midnight", entries[0][1]);
  assertEquals(12, entries[1][0].hours);
  assertEquals(30, entries[1][0].minutes);
  assertEquals("noon", entries[1][1]);
  assertEquals(14, entries[2][0].hours);
  assertEquals(500, entries[2][0].milliseconds);
  assertEquals("afternoon", entries[2][1]);
  assertEquals(23, entries[3][0].hours);
  assertEquals(999, entries[3][0].milliseconds);
  assertEquals("eod", entries[3][1]);
}

// all timeonly variations as values — no space
{
  const m = RDN.parse(
    'Map{' +
      '"midnight"=>@00:00:00,' +
      '"noon"=>@12:30:00,' +
      '"afternoon"=>@14:30:00.500,' +
      '"eod"=>@23:59:59.999' +
    '}'
  );
  assertEquals(4, m.size);
  assertEquals(0, m.get("midnight").hours);
  assertEquals(0, m.get("midnight").milliseconds);
  assertEquals(12, m.get("noon").hours);
  assertEquals(30, m.get("noon").minutes);
  assertEquals(14, m.get("afternoon").hours);
  assertEquals(500, m.get("afternoon").milliseconds);
  assertEquals(23, m.get("eod").hours);
  assertEquals(59, m.get("eod").seconds);
  assertEquals(999, m.get("eod").milliseconds);
}

// all timeonly variations as values — with space
{
  const m = RDN.parse(
    'Map{' +
      '"midnight" => @00:00:00, ' +
      '"noon" => @12:30:00, ' +
      '"afternoon" => @14:30:00.500, ' +
      '"eod" => @23:59:59.999' +
    '}'
  );
  assertEquals(4, m.size);
  assertEquals(0, m.get("midnight").hours);
  assertEquals(12, m.get("noon").hours);
  assertEquals(500, m.get("afternoon").milliseconds);
  assertEquals(999, m.get("eod").milliseconds);
}

// ── Duration key: all format variations ──────────────────────────────

// date-only components — no space / with space
{
  const m1 = RDN.parse('Map{@P1D=>"1day"}');
  const e1 = mapEntry(m1, 0);
  assertEquals("P1D", e1.key.iso);
  assertEquals("1day", e1.value);

  const m2 = RDN.parse('Map{@P1D => "1day"}');
  const e2 = mapEntry(m2, 0);
  assertEquals("P1D", e2.key.iso);
  assertEquals("1day", e2.value);
}

{
  const m1 = RDN.parse('Map{@P1Y=>"1year"}');
  const e1 = mapEntry(m1, 0);
  assertEquals("P1Y", e1.key.iso);
  assertEquals("1year", e1.value);

  const m2 = RDN.parse('Map{@P1Y => "1year"}');
  const e2 = mapEntry(m2, 0);
  assertEquals("P1Y", e2.key.iso);
  assertEquals("1year", e2.value);
}

{
  const m1 = RDN.parse('Map{@P2M=>"2months"}');
  assertEquals("P2M", mapEntry(m1, 0).key.iso);

  const m2 = RDN.parse('Map{@P2M => "2months"}');
  assertEquals("P2M", mapEntry(m2, 0).key.iso);
}

// multi-component date — no space / with space
{
  const m1 = RDN.parse('Map{@P1Y2M3D=>"ymd"}');
  assertEquals("P1Y2M3D", mapEntry(m1, 0).key.iso);
  assertEquals("ymd", mapEntry(m1, 0).value);

  const m2 = RDN.parse('Map{@P1Y2M3D => "ymd"}');
  assertEquals("P1Y2M3D", mapEntry(m2, 0).key.iso);
}

// time-only components — no space / with space
{
  const m1 = RDN.parse('Map{@PT1H=>"1hour"}');
  assertEquals("PT1H", mapEntry(m1, 0).key.iso);
  assertEquals("1hour", mapEntry(m1, 0).value);

  const m2 = RDN.parse('Map{@PT1H => "1hour"}');
  assertEquals("PT1H", mapEntry(m2, 0).key.iso);
}

{
  const m1 = RDN.parse('Map{@PT30M=>"30min"}');
  assertEquals("PT30M", mapEntry(m1, 0).key.iso);

  const m2 = RDN.parse('Map{@PT30M => "30min"}');
  assertEquals("PT30M", mapEntry(m2, 0).key.iso);
}

{
  const m1 = RDN.parse('Map{@PT45S=>"45sec"}');
  assertEquals("PT45S", mapEntry(m1, 0).key.iso);

  const m2 = RDN.parse('Map{@PT45S => "45sec"}');
  assertEquals("PT45S", mapEntry(m2, 0).key.iso);
}

// multi-component time — no space / with space
{
  const m1 = RDN.parse('Map{@PT1H30M=>"1h30m"}');
  assertEquals("PT1H30M", mapEntry(m1, 0).key.iso);

  const m2 = RDN.parse('Map{@PT1H30M => "1h30m"}');
  assertEquals("PT1H30M", mapEntry(m2, 0).key.iso);
}

{
  const m1 = RDN.parse('Map{@PT0H0M0S=>"zero"}');
  assertEquals("PT0H0M0S", mapEntry(m1, 0).key.iso);

  const m2 = RDN.parse('Map{@PT0H0M0S => "zero"}');
  assertEquals("PT0H0M0S", mapEntry(m2, 0).key.iso);
}

// full date+time duration — no space / with space
{
  const m1 = RDN.parse('Map{@P1Y2M3DT4H5M6S=>"full"}');
  assertEquals("P1Y2M3DT4H5M6S", mapEntry(m1, 0).key.iso);
  assertEquals("full", mapEntry(m1, 0).value);

  const m2 = RDN.parse('Map{@P1Y2M3DT4H5M6S => "full"}');
  assertEquals("P1Y2M3DT4H5M6S", mapEntry(m2, 0).key.iso);
}

// mixed date+time — no space / with space
{
  const m1 = RDN.parse('Map{@P1DT12H=>"1d12h"}');
  assertEquals("P1DT12H", mapEntry(m1, 0).key.iso);

  const m2 = RDN.parse('Map{@P1DT12H => "1d12h"}');
  assertEquals("P1DT12H", mapEntry(m2, 0).key.iso);
}

// all duration formats as keys in one map
{
  const m = RDN.parse(
    'Map{' +
      '@P1D => "day", ' +
      '@P1Y => "year", ' +
      '@P2M => "months", ' +
      '@P1Y2M3D => "ymd", ' +
      '@PT1H => "hour", ' +
      '@PT30M => "min", ' +
      '@PT45S => "sec", ' +
      '@PT1H30M => "hm", ' +
      '@PT0H0M0S => "zero", ' +
      '@P1Y2M3DT4H5M6S => "full", ' +
      '@P1DT12H => "mixed"' +
    '}'
  );
  assertEquals(11, m.size);
  const entries = [...m];
  assertEquals("P1D", entries[0][0].iso);
  assertEquals("day", entries[0][1]);
  assertEquals("P1Y", entries[1][0].iso);
  assertEquals("year", entries[1][1]);
  assertEquals("P2M", entries[2][0].iso);
  assertEquals("months", entries[2][1]);
  assertEquals("P1Y2M3D", entries[3][0].iso);
  assertEquals("ymd", entries[3][1]);
  assertEquals("PT1H", entries[4][0].iso);
  assertEquals("hour", entries[4][1]);
  assertEquals("PT30M", entries[5][0].iso);
  assertEquals("min", entries[5][1]);
  assertEquals("PT45S", entries[6][0].iso);
  assertEquals("sec", entries[6][1]);
  assertEquals("PT1H30M", entries[7][0].iso);
  assertEquals("hm", entries[7][1]);
  assertEquals("PT0H0M0S", entries[8][0].iso);
  assertEquals("zero", entries[8][1]);
  assertEquals("P1Y2M3DT4H5M6S", entries[9][0].iso);
  assertEquals("full", entries[9][1]);
  assertEquals("P1DT12H", entries[10][0].iso);
  assertEquals("mixed", entries[10][1]);
}

// all duration formats as values — no space
{
  const m = RDN.parse(
    'Map{' +
      '"day"=>@P1D,' +
      '"year"=>@P1Y,' +
      '"months"=>@P2M,' +
      '"ymd"=>@P1Y2M3D,' +
      '"hour"=>@PT1H,' +
      '"min"=>@PT30M,' +
      '"sec"=>@PT45S,' +
      '"hm"=>@PT1H30M,' +
      '"zero"=>@PT0H0M0S,' +
      '"full"=>@P1Y2M3DT4H5M6S,' +
      '"mixed"=>@P1DT12H' +
    '}'
  );
  assertEquals(11, m.size);
  assertEquals("P1D", m.get("day").iso);
  assertEquals("P1Y", m.get("year").iso);
  assertEquals("P2M", m.get("months").iso);
  assertEquals("P1Y2M3D", m.get("ymd").iso);
  assertEquals("PT1H", m.get("hour").iso);
  assertEquals("PT30M", m.get("min").iso);
  assertEquals("PT45S", m.get("sec").iso);
  assertEquals("PT1H30M", m.get("hm").iso);
  assertEquals("PT0H0M0S", m.get("zero").iso);
  assertEquals("P1Y2M3DT4H5M6S", m.get("full").iso);
  assertEquals("P1DT12H", m.get("mixed").iso);
}

// all duration formats as values — with space
{
  const m = RDN.parse(
    'Map{' +
      '"day" => @P1D, ' +
      '"year" => @P1Y, ' +
      '"months" => @P2M, ' +
      '"ymd" => @P1Y2M3D, ' +
      '"hour" => @PT1H, ' +
      '"min" => @PT30M, ' +
      '"sec" => @PT45S, ' +
      '"hm" => @PT1H30M, ' +
      '"zero" => @PT0H0M0S, ' +
      '"full" => @P1Y2M3DT4H5M6S, ' +
      '"mixed" => @P1DT12H' +
    '}'
  );
  assertEquals(11, m.size);
  assertEquals("P1D", m.get("day").iso);
  assertEquals("P1Y", m.get("year").iso);
  assertEquals("P2M", m.get("months").iso);
  assertEquals("P1Y2M3D", m.get("ymd").iso);
  assertEquals("PT1H", m.get("hour").iso);
  assertEquals("PT30M", m.get("min").iso);
  assertEquals("PT45S", m.get("sec").iso);
  assertEquals("PT1H30M", m.get("hm").iso);
  assertEquals("PT0H0M0S", m.get("zero").iso);
  assertEquals("P1Y2M3DT4H5M6S", m.get("full").iso);
  assertEquals("P1DT12H", m.get("mixed").iso);
}

// regexp key — no space / with space
{
  const m1 = RDN.parse('Map{/^test$/i=>"pattern"}');
  const e1 = mapEntry(m1, 0);
  assertTrue(e1.key instanceof RegExp);
  assertEquals("^test$", e1.key.source);
  assertTrue(e1.key.ignoreCase);
  assertEquals("pattern", e1.value);

  const m2 = RDN.parse('Map{/^test$/i => "pattern"}');
  const e2 = mapEntry(m2, 0);
  assertTrue(e2.key instanceof RegExp);
  assertEquals("^test$", e2.key.source);
  assertEquals("pattern", e2.value);
}

// binary base64 key — no space / with space
{
  const m1 = RDN.parse('Map{b"SGVsbG8="=>"b64"}');
  const e1 = mapEntry(m1, 0);
  assertTrue(e1.key instanceof Uint8Array);
  assertEquals(5, e1.key.length);
  assertEquals(72, e1.key[0]);  // 'H'
  assertEquals("b64", e1.value);

  const m2 = RDN.parse('Map{b"SGVsbG8=" => "b64"}');
  const e2 = mapEntry(m2, 0);
  assertTrue(e2.key instanceof Uint8Array);
  assertEquals(5, e2.key.length);
  assertEquals("b64", e2.value);
}

// binary hex key — no space / with space
{
  const m1 = RDN.parse('Map{x"FF00"=>"hex"}');
  const e1 = mapEntry(m1, 0);
  assertTrue(e1.key instanceof Uint8Array);
  assertEquals(2, e1.key.length);
  assertEquals(0xFF, e1.key[0]);
  assertEquals(0x00, e1.key[1]);
  assertEquals("hex", e1.value);

  const m2 = RDN.parse('Map{x"FF00" => "hex"}');
  const e2 = mapEntry(m2, 0);
  assertTrue(e2.key instanceof Uint8Array);
  assertEquals(2, e2.key.length);
  assertEquals("hex", e2.value);
}

// array key — no space / with space
{
  const m1 = RDN.parse('Map{[1, 2]=>"arr"}');
  const e1 = mapEntry(m1, 0);
  assertTrue(Array.isArray(e1.key));
  assertEquals(2, e1.key.length);
  assertEquals(1, e1.key[0]);
  assertEquals(2, e1.key[1]);
  assertEquals("arr", e1.value);

  const m2 = RDN.parse('Map{[1, 2] => "arr"}');
  const e2 = mapEntry(m2, 0);
  assertTrue(Array.isArray(e2.key));
  assertEquals(2, e2.key.length);
  assertEquals("arr", e2.value);
}

// object key — no space / with space
{
  const m1 = RDN.parse('Map{{"a": 1}=>"obj"}');
  const e1 = mapEntry(m1, 0);
  assertEquals(1, e1.key.a);
  assertEquals("obj", e1.value);

  const m2 = RDN.parse('Map{{"a": 1} => "obj"}');
  const e2 = mapEntry(m2, 0);
  assertEquals(1, e2.key.a);
  assertEquals("obj", e2.value);
}

// nested map key — no space / with space
{
  const m1 = RDN.parse('Map{Map{"x" => 1}=>"nested"}');
  const e1 = mapEntry(m1, 0);
  assertTrue(e1.key instanceof Map);
  assertEquals(1, e1.key.get("x"));
  assertEquals("nested", e1.value);

  const m2 = RDN.parse('Map{Map{"x" => 1} => "nested"}');
  const e2 = mapEntry(m2, 0);
  assertTrue(e2.key instanceof Map);
  assertEquals(1, e2.key.get("x"));
  assertEquals("nested", e2.value);
}

// set key — no space / with space
{
  const m1 = RDN.parse('Map{Set{1, 2}=>"set"}');
  const e1 = mapEntry(m1, 0);
  assertTrue(e1.key instanceof Set);
  assertEquals(2, e1.key.size);
  assertTrue(e1.key.has(1));
  assertTrue(e1.key.has(2));
  assertEquals("set", e1.value);

  const m2 = RDN.parse('Map{Set{1, 2} => "set"}');
  const e2 = mapEntry(m2, 0);
  assertTrue(e2.key instanceof Set);
  assertEquals(2, e2.key.size);
  assertEquals("set", e2.value);
}

// tuple key — no space / with space
{
  const m1 = RDN.parse('Map{(1, 2, 3)=>"tuple"}');
  const e1 = mapEntry(m1, 0);
  assertTrue(Array.isArray(e1.key));
  assertEquals(3, e1.key.length);
  assertEquals("tuple", e1.value);

  const m2 = RDN.parse('Map{(1, 2, 3) => "tuple"}');
  const e2 = mapEntry(m2, 0);
  assertTrue(Array.isArray(e2.key));
  assertEquals(3, e2.key.length);
  assertEquals("tuple", e2.value);
}

// ── All types as values ──────────────────────────────────────────────

// All types as values with no space around arrow
{
  const m = RDN.parse(
    'Map{' +
      '"k_null"=>null,' +
      '"k_true"=>true,' +
      '"k_false"=>false,' +
      '"k_int"=>42,' +
      '"k_float"=>3.14,' +
      '"k_nan"=>NaN,' +
      '"k_inf"=>Infinity,' +
      '"k_ninf"=>-Infinity,' +
      '"k_bigint"=>999999999999999999n,' +
      '"k_string"=>"hello",' +
      '"k_date"=>@2024-01-15T10:30:00.000Z,' +
      '"k_time"=>@14:30:00,' +
      '"k_dur"=>@P1D,' +
      '"k_regex"=>/^test$/i,' +
      '"k_b64"=>b"SGVsbG8=",' +
      '"k_hex"=>x"FF00",' +
      '"k_arr"=>[1, 2],' +
      '"k_obj"=>{"a": 1},' +
      '"k_map"=>Map{"x" => 1},' +
      '"k_set"=>Set{1, 2},' +
      '"k_tuple"=>(1, 2)' +
    '}'
  );
  assertEquals(21, m.size);
  assertEquals(null, m.get("k_null"));
  assertEquals(true, m.get("k_true"));
  assertEquals(false, m.get("k_false"));
  assertEquals(42, m.get("k_int"));
  assertEquals(3.14, m.get("k_float"));
  assertTrue(isNaN(m.get("k_nan")));
  assertEquals(Infinity, m.get("k_inf"));
  assertEquals(-Infinity, m.get("k_ninf"));
  assertEquals(999999999999999999n, m.get("k_bigint"));
  assertEquals("hello", m.get("k_string"));
  assertTrue(m.get("k_date") instanceof Date);
  assertEquals(2024, m.get("k_date").getUTCFullYear());
  assertEquals(14, m.get("k_time").hours);
  assertEquals("P1D", m.get("k_dur").iso);
  assertTrue(m.get("k_regex") instanceof RegExp);
  assertEquals("^test$", m.get("k_regex").source);
  assertTrue(m.get("k_b64") instanceof Uint8Array);
  assertEquals(5, m.get("k_b64").length);
  assertTrue(m.get("k_hex") instanceof Uint8Array);
  assertEquals(2, m.get("k_hex").length);
  assertTrue(Array.isArray(m.get("k_arr")));
  assertEquals(2, m.get("k_arr").length);
  assertEquals(1, m.get("k_obj").a);
  assertTrue(m.get("k_map") instanceof Map);
  assertEquals(1, m.get("k_map").get("x"));
  assertTrue(m.get("k_set") instanceof Set);
  assertEquals(2, m.get("k_set").size);
  assertTrue(Array.isArray(m.get("k_tuple")));
  assertEquals(2, m.get("k_tuple").length);
}

// All types as values with spaces around arrow
{
  const m = RDN.parse(
    'Map{' +
      '"k_null" => null, ' +
      '"k_true" => true, ' +
      '"k_false" => false, ' +
      '"k_int" => 42, ' +
      '"k_float" => 3.14, ' +
      '"k_nan" => NaN, ' +
      '"k_inf" => Infinity, ' +
      '"k_ninf" => -Infinity, ' +
      '"k_bigint" => 999999999999999999n, ' +
      '"k_string" => "hello", ' +
      '"k_date" => @2024-01-15T10:30:00.000Z, ' +
      '"k_time" => @14:30:00, ' +
      '"k_dur" => @P1D, ' +
      '"k_regex" => /^test$/i, ' +
      '"k_b64" => b"SGVsbG8=", ' +
      '"k_hex" => x"FF00", ' +
      '"k_arr" => [1, 2], ' +
      '"k_obj" => {"a": 1}, ' +
      '"k_map" => Map{"x" => 1}, ' +
      '"k_set" => Set{1, 2}, ' +
      '"k_tuple" => (1, 2)' +
    '}'
  );
  assertEquals(21, m.size);
  assertEquals(null, m.get("k_null"));
  assertEquals(true, m.get("k_true"));
  assertEquals(false, m.get("k_false"));
  assertEquals(42, m.get("k_int"));
  assertEquals(3.14, m.get("k_float"));
  assertTrue(isNaN(m.get("k_nan")));
  assertEquals(Infinity, m.get("k_inf"));
  assertEquals(-Infinity, m.get("k_ninf"));
  assertEquals(999999999999999999n, m.get("k_bigint"));
  assertEquals("hello", m.get("k_string"));
  assertTrue(m.get("k_date") instanceof Date);
  assertEquals(14, m.get("k_time").hours);
  assertEquals("P1D", m.get("k_dur").iso);
  assertTrue(m.get("k_regex") instanceof RegExp);
  assertTrue(m.get("k_b64") instanceof Uint8Array);
  assertTrue(m.get("k_hex") instanceof Uint8Array);
  assertTrue(Array.isArray(m.get("k_arr")));
  assertEquals(1, m.get("k_obj").a);
  assertTrue(m.get("k_map") instanceof Map);
  assertTrue(m.get("k_set") instanceof Set);
  assertTrue(Array.isArray(m.get("k_tuple")));
}

// ── Whitespace variations around arrow ───────────────────────────────

// Multiple spaces around arrow
{
  const m = RDN.parse('Map{"a"  =>  "b"}');
  assertEquals("b", m.get("a"));
}

// Tab around arrow
{
  const m = RDN.parse('Map{"a"\t=>\t"b"}');
  assertEquals("b", m.get("a"));
}

// Newlines around arrow
{
  const m = RDN.parse('Map{"a"\n=>\n"b"}');
  assertEquals("b", m.get("a"));
}

// Mixed whitespace: tabs, spaces, newlines
{
  const m = RDN.parse('Map{\n\t"key" \t =>\n "value"\n}');
  assertEquals("value", m.get("key"));
}

// No whitespace anywhere (compact form)
{
  const m = RDN.parse('Map{"a"=>"b","c"=>"d"}');
  assertEquals(2, m.size);
  assertEquals("b", m.get("a"));
  assertEquals("d", m.get("c"));
}

// Implicit map (brace-disambiguated) — no space around arrow
{
  const m = RDN.parse('{"a"=>"b"}');
  assertTrue(m instanceof Map);
  assertEquals("b", m.get("a"));
}

// Implicit map — with whitespace variations
{
  const m = RDN.parse('{ "a"  =>  "b" , "c"  =>  "d" }');
  assertTrue(m instanceof Map);
  assertEquals(2, m.size);
  assertEquals("b", m.get("a"));
  assertEquals("d", m.get("c"));
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

// ── Replacer tests ──────────────────────────────────────────────────

// Object property filtering (return undefined to omit)
{
  const obj = {a: 1, b: 2, c: 3};
  const s = RDN.stringify(obj, (key, value) => key === "b" ? undefined : value);
  const result = RDN.parse(s);
  assertEquals(1, result.a);
  assertEquals(3, result.c);
  assertEquals(undefined, result.b);
}

// Array element transformation
{
  const arr = [1, 2, 3, 4];
  const s = RDN.stringify(arr, (key, value) => typeof value === "number" ? value * 2 : value);
  const result = RDN.parse(s);
  assertEquals([2, 4, 6, 8], result);
}

// Root-level replacement (key="")
{
  const s = RDN.stringify(42, (key, value) => {
    if (key === "") return "replaced";
    return value;
  });
  assertEquals('"replaced"', s);
}

// Map entry filtering with simple keys
{
  const m = new Map([["a", 1], ["b", 2], ["c", 3]]);
  const s = RDN.stringify(m, (key, value) => key === "b" ? undefined : value);
  const result = RDN.parse(s);
  assertTrue(result instanceof Map);
  assertEquals(2, result.size);
  assertEquals(1, result.get("a"));
  assertEquals(3, result.get("c"));
  assertFalse(result.has("b"));
}

// Map entry filtering with numeric keys
{
  const m = new Map([[1, "one"], [2, "two"], [3, "three"]]);
  const s = RDN.stringify(m, (key, value) => key === 2 ? undefined : value);
  const result = RDN.parse(s);
  assertTrue(result instanceof Map);
  assertEquals(2, result.size);
  assertEquals("one", result.get(1));
  assertEquals("three", result.get(3));
}

// Set element filtering
{
  const s = new Set([1, 2, 3, 4, 5]);
  const str = RDN.stringify(s, (key, value) => value % 2 === 0 ? undefined : value);
  const result = RDN.parse(str);
  assertTrue(result instanceof Set);
  assertEquals(3, result.size);
  assertTrue(result.has(1));
  assertTrue(result.has(3));
  assertTrue(result.has(5));
}

// All-filtered Map → Map{}
{
  const m = new Map([["a", 1]]);
  const s = RDN.stringify(m, (key, value) => typeof value === "number" ? undefined : value);
  assertEquals("Map{}", s);
}

// All-filtered Set → Set{}
{
  const s = new Set([1, 2, 3]);
  const str = RDN.stringify(s, (key, value) => typeof value === "number" ? undefined : value);
  assertEquals("Set{}", str);
}

// Non-callable replacer → ignored (no filtering)
{
  const obj = {a: 1, b: 2};
  const s1 = RDN.stringify(obj);
  const s2 = RDN.stringify(obj, null);
  const s3 = RDN.stringify(obj, 42);
  const s4 = RDN.stringify(obj, "not a function");
  assertEquals(s1, s2);
  assertEquals(s1, s3);
  assertEquals(s1, s4);
}

// Nested structures with replacer
{
  const obj = {a: {x: 1, y: 2}, b: {x: 3, y: 4}};
  const s = RDN.stringify(obj, (key, value) => key === "y" ? undefined : value);
  const result = RDN.parse(s);
  assertEquals(1, result.a.x);
  assertEquals(undefined, result.a.y);
  assertEquals(3, result.b.x);
  assertEquals(undefined, result.b.y);
}

// Replacer value transformation on objects
{
  const obj = {name: "test", count: 5};
  const s = RDN.stringify(obj, (key, value) => {
    if (typeof value === "string" && key !== "") return value.toUpperCase();
    return value;
  });
  const result = RDN.parse(s);
  assertEquals("TEST", result.name);
  assertEquals(5, result.count);
}

// ── Reviver tests ───────────────────────────────────────────────────

// Object value transformation
{
  const result = RDN.parse('{"a": 1, "b": 2, "c": 3}', (key, value) => {
    if (typeof value === "number") return value * 10;
    return value;
  });
  assertEquals(10, result.a);
  assertEquals(20, result.b);
  assertEquals(30, result.c);
}

// Object property deletion (return undefined)
{
  const result = RDN.parse('{"a": 1, "b": 2, "c": 3}', (key, value) => {
    if (key === "b") return undefined;
    return value;
  });
  assertEquals(1, result.a);
  assertEquals(undefined, result.b);
  assertEquals(3, result.c);
}

// Array element transformation
{
  const result = RDN.parse('[1, 2, 3]', (key, value) => {
    if (typeof value === "number") return value + 100;
    return value;
  });
  assertEquals([101, 102, 103], result);
}

// Map value transformation with simple keys
{
  const result = RDN.parse('Map{"a" => 1, "b" => 2}', (key, value) => {
    if (typeof value === "number") return value * 5;
    return value;
  });
  assertTrue(result instanceof Map);
  assertEquals(5, result.get("a"));
  assertEquals(10, result.get("b"));
}

// Map entry removal (return undefined for map entry)
{
  const result = RDN.parse('Map{"a" => 1, "b" => 2, "c" => 3}', (key, value) => {
    if (key === "b") return undefined;
    return value;
  });
  assertTrue(result instanceof Map);
  assertEquals(2, result.size);
  assertEquals(1, result.get("a"));
  assertEquals(3, result.get("c"));
  assertFalse(result.has("b"));
}

// Set value transformation
{
  const result = RDN.parse('Set{1, 2, 3}', (key, value) => {
    if (typeof value === "number") return value * 10;
    return value;
  });
  assertTrue(result instanceof Set);
  assertEquals(3, result.size);
  assertTrue(result.has(10));
  assertTrue(result.has(20));
  assertTrue(result.has(30));
}

// Set element removal (return undefined)
{
  const result = RDN.parse('Set{1, 2, 3, 4, 5}', (key, value) => {
    if (value === 3) return undefined;
    return value;
  });
  assertTrue(result instanceof Set);
  assertEquals(4, result.size);
  assertTrue(result.has(1));
  assertTrue(result.has(2));
  assertFalse(result.has(3));
  assertTrue(result.has(4));
  assertTrue(result.has(5));
}

// Non-callable reviver → ignored
{
  const result1 = RDN.parse('{"a": 1}');
  const result2 = RDN.parse('{"a": 1}', null);
  const result3 = RDN.parse('{"a": 1}', 42);
  assertEquals(result1.a, result2.a);
  assertEquals(result1.a, result3.a);
}

// Nested structures with reviver (bottom-up order)
{
  const order = [];
  RDN.parse('{"a": {"x": 1}, "b": 2}', (key, value) => {
    if (key !== "") order.push(key);
    return value;
  });
  // Bottom-up: inner properties first, then outer
  assertEquals("x", order[0]);
  assertEquals("a", order[1]);
  assertEquals("b", order[2]);
}

// Roundtrip with replacer + reviver
{
  const original = {a: 1, b: 2, c: 3};
  // Replacer doubles values
  const encoded = RDN.stringify(original, (key, value) => {
    if (typeof value === "number") return value * 2;
    return value;
  });
  // Reviver halves them back
  const decoded = RDN.parse(encoded, (key, value) => {
    if (typeof value === "number") return value / 2;
    return value;
  });
  assertEquals(1, decoded.a);
  assertEquals(2, decoded.b);
  assertEquals(3, decoded.c);
}

// RDN.parse.length and RDN.stringify.length should be 2
assertEquals(2, RDN.parse.length);
assertEquals(2, RDN.stringify.length);
