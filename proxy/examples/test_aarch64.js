var fuzz = require("../fuzz");

// { traps: 'all' } is needed for stalking
var func_handle_stdin = new NativeFunction(DebugSymbol.fromName("_Z11write2stdinPcl").address, "int", ['pointer', 'uint64'], { traps: 'all' });
var func_handle_quit_stdin = new NativeFunction(DebugSymbol.fromName("_Z16quit_write2stdinv").address, 'void', [], { traps: 'all' });
var func_handle_setup_shm = new NativeFunction(DebugSymbol.fromName("setup_shm").address, 'void', [], { traps: 'all' });
var func_handle_afl_manual_init = new NativeFunction(DebugSymbol.fromName("__afl_manual_init").address, 'void', [], { traps: 'all' });
var func_handle = new NativeFunction(DebugSymbol.fromName("main").address, "int", ['int', 'pointer'], { traps: 'all' });

fuzz.fuzz_one_input = function (/* Uint8Array */ payload) {
  var payload_mem = Memory.alloc(payload.length);

  Memory.writeByteArray(payload_mem, payload, payload.length);

  func_handle_setup_shm();

  func_handle_afl_manual_init();

  var ret = func_handle_stdin(payload_mem, payload.length);
  if (ret != 0) {
    return;
  }

  ret = func_handle(1, ptr(0));
  if (ret != 0) {
    return;
  }

  Module.enumerateSymbolsSync("libaflfuzzer.so")
    .forEach(function(s){
      if (s.name === "trace_bits") {
        var trace_bits = s.address.readPointer();
        send({"event": "trace_bits"}, trace_bits.readByteArray(fuzz.config.MAP_SIZE));
      }
   });

  func_handle_quit_stdin();

  send({"event": "done"});
}
