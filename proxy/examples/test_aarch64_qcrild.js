var fuzz = require("../fuzz");

// { traps: 'all' } is needed for stalking
var func_handle_stdin = new NativeFunction(DebugSymbol.fromName("_Z11write2stdinPcl").address, "int", ['pointer', 'uint64'], { traps: 'all' });
var func_handle_quit_stdin = new NativeFunction(DebugSymbol.fromName("_Z16quit_write2stdinv").address, 'void', [], { traps: 'all' });
var func_handle_setup_shm = new NativeFunction(DebugSymbol.fromName("setup_shm").address, 'void', [], { traps: 'all' });
var func_handle_afl_manual_init = new NativeFunction(DebugSymbol.fromName("__afl_manual_init").address, 'void', [], { traps: 'all' });
var func_handle = new NativeFunction(DebugSymbol.fromName("_Z12dispatch_msgv").address, "void", [], { traps: 'all' });
var func_handle_set_affinity = new NativeFunction(DebugSymbol.fromName("set_affinity").address, "void", ['int'], { traps: 'all' });

var target = "qcrild";


var zeroed_bits = new Uint8Array(fuzz.config.MAP_SIZE);

fuzz.fuzz_one_input = function (/* Uint8Array */ payload) {

  try {
    func_handle_set_affinity(7);
  } catch(err) {
    console.log("set affinity failed");
  }

  Module.enumerateSymbolsSync(target)
    .forEach(function(s){
      if (s.name === "__afl_area_ptr") {
        var trace_bits = s.address.readPointer();
	Memory.writeByteArray(trace_bits, zeroed_bits);
      }
   });

  var payload_mem = payload.buffer.unwrap();

  func_handle_setup_shm();

  func_handle_afl_manual_init();

  var ret = func_handle_stdin(payload_mem, payload.length);
  if (ret != 0) {
    return;
  }

  try {
    func_handle();
  } catch (err) {
    if (err.type !== undefined) {
      send({
        "event": "crash",
	"err": err
      });
    } else if (err.$handle !== undefined) {
      send({
        "event": "exception",
	"err": err
      });
    } else {
      send({
        "event": "other",
	"err": err
      });
    }
  }

  Module.enumerateSymbolsSync(target)
    .forEach(function(s){
      if (s.name === "__afl_area_ptr") {
        var trace_bits = s.address.readPointer();
        send({"event": "trace_bits"}, trace_bits.readByteArray(fuzz.config.MAP_SIZE));
      }
   });

  func_handle_quit_stdin();

  send({"event": "done"});
}
