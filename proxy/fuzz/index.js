var utils = require("./utils.js");

exports.fuzz_one_input = null;

exports.fuzz_one = function() {
  if (exports.fuzz_one_input === null) {
    throw "error: fuzz_one_input not set! Cannot start fuzz!";
  }

  var buf = undefined;

  send({
    "event": "input"
  });

  var op = recv("input", function(val) {
    if (val.buf === null) {
      buf = null;
      return;
    }
    buf = utils.hex_to_arrbuf(val.buf);
  });

  op.wait();
  if (buf === null) return;

  var payload = new Uint8Array(buf);

  exports.fuzz_one_input(payload);
}

rpc.exports.fuzzer = function() {
  exports.fuzz_one();
}
