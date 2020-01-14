env = {
  "LD_LIBRARY_PATH": "/system/lib64/extractors",
  "LD_PRELOAD": "/data/local/tmp/libwrite2stdin.so /data/local/tmp/libaflfuzzer.so",
  "__AFL_DEFER_FORKSRV": "true"
}
