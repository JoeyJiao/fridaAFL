all:
	gcc -O0 -g write2stdin.cpp -shared -o libwrite2stdin.so
	gcc -O0 -g afl-fuzzer.c -shared -fPIC -o libaflfuzzer.so -Wno-implicit-function-declaration -Wno-int-conversion

clean:
	rm -rf libaflfuzzer.so libwrite2stdin.so
