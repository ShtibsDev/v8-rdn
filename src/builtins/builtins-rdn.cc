// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// RDN builtins — parse and stringify for the RDN data format.

#include "src/builtins/builtins-utils-inl.h"
#include "src/builtins/builtins.h"
#include "src/execution/isolate.h"
#include "src/json/rdn-parser.h"
#include "src/json/rdn-stringifier.h"
#include "src/objects/objects-inl.h"

namespace v8 {
namespace internal {

// RDN.parse(text, reviver)
BUILTIN(RdnParse) {
  HandleScope scope(isolate);
  Handle<Object> source = args.atOrUndefined(isolate, 1);
  Handle<Object> reviver = args.atOrUndefined(isolate, 2);
  Handle<String> string;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, string,
                                     Object::ToString(isolate, source));
  string = String::Flatten(isolate, string);
  RETURN_RESULT_OR_FAILURE(
      isolate,
      String::IsOneByteRepresentationUnderneath(*string)
          ? RdnParser<uint8_t>::Parse(isolate, string, reviver)
          : RdnParser<uint16_t>::Parse(isolate, string, reviver));
}

// RDN.stringify(value, replacer)
BUILTIN(RdnStringify) {
  HandleScope scope(isolate);
  Handle<Object> object = args.atOrUndefined(isolate, 1);
  Handle<Object> replacer = args.atOrUndefined(isolate, 2);
  RETURN_RESULT_OR_FAILURE(isolate, RdnStringify(isolate, object, replacer));
}

}  // namespace internal
}  // namespace v8
