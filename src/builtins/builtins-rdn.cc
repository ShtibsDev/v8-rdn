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

// RDN.parse(text)
BUILTIN(RdnParse) {
  HandleScope scope(isolate);
  Handle<Object> source = args.atOrUndefined(isolate, 1);
  Handle<String> string;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, string,
                                     Object::ToString(isolate, source));
  string = String::Flatten(isolate, string);
  RETURN_RESULT_OR_FAILURE(
      isolate,
      String::IsOneByteRepresentationUnderneath(*string)
          ? RdnParser<uint8_t>::Parse(isolate, string)
          : RdnParser<uint16_t>::Parse(isolate, string));
}

// RDN.stringify(value)
BUILTIN(RdnStringify) {
  HandleScope scope(isolate);
  Handle<Object> object = args.atOrUndefined(isolate, 1);
  RETURN_RESULT_OR_FAILURE(isolate, RdnStringify(isolate, object));
}

}  // namespace internal
}  // namespace v8
