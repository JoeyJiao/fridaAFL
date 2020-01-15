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
./run.sh -b "python3 ./proxy/proxy.py -U -s -t /data/local/tmp/fuzz-mm-parser" -i input -o findings -m none -j 1
```

# Write a new test case
Refer to `examples/test_aarch64.js`.

# TODO
+ Support remote fuzzer with fork server
+ Performance optimization
+ FIX many target binary created while requested only one
