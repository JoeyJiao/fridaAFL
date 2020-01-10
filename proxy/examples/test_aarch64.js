var fuzz = require("../fuzz");

var TARGET_FUNCTION_STDIN = DebugSymbol.fromName("_Z11write2stdinPcl").address; // write2stdin
var TARGET_FUNCTION_QUIT_STDIN = DebugSymbol.fromName("_Z16quit_write2stdinv").address; // quit_write2stdin
var TARGET_FUNCTION = DebugSymbol.fromName("main").address;
var RET_TYPE = "int";
var ARGS_TYPES_STDIN = ['pointer', 'uint64'];
var ARGS_TYPES = ['int', 'pointer'];

// { traps: 'all' } is needed for stalking
var func_handle_stdin = new NativeFunction(TARGET_FUNCTION_STDIN, RET_TYPE, ARGS_TYPES_STDIN, { traps: 'all' });
var func_handle_quit_stdin = new NativeFunction(TARGET_FUNCTION_QUIT_STDIN, 'void', [], { traps: 'all' });
var func_handle = new NativeFunction(TARGET_FUNCTION, RET_TYPE, ARGS_TYPES, { traps: 'all' });

fuzz.fuzz_one_input = function (/* Uint8Array */ payload) {
  var payload_mem = Memory.alloc(payload.length);

  Memory.writeByteArray(payload_mem, payload, payload.length);

  var ret = func_handle_stdin(payload_mem, payload.length);
  if (ret != 0) {
    return;
  }

  ret = func_handle(1, ptr(0));
  if (ret != 0) {
    return;
  }

  ret = func_handle_quit_stdin();
  if (ret != 0) {
    return;
  }

  send({"event": "done"});
}
