# fridaAFL
fridaAFL is frida + AFL based remote fuzz engine which run afl-fuzz on host while fuzzing target binary on target machine.

![design](assets/fridaAFL.PNG)

# Install
```bash
git clone https://github.com/JoeyJiao/fridaAFL
cd fridaAFL
pip3 install --user Cython
cd python-afl
python3 setup.py install --user
cd ../proxy
pip3 install --user frida
npm install
./node_modules/.bin/frida-compile examples/test_aarch64.js  -o proxy.js
cd -
```

# Run
```bash
./python-afl/py-afl-fuzz -m none -i input -o findings -- ./proxy/proxy.py -t /data/local/tmp/fuzz-mm-parser
```

# Write a new test case
Refer to `examples/test_aarch64.js`.

# TODO
+ Support remote fuzzer with fork server
+ ~~Write fuzzer trace_bits to afl-fuzz on host~~
+ ~~Avoid fuzzing frida proxy code~~
+ Performance optimization
+ Kill target binary process when timeout
