# QMSan

QEMU-based multi-architecture MemorySanitizer (QMSan) is a solution to detect Use-of-Uninitialized Memory (UUM) errors. Currently, it supports both amd64 and aarch64 architectures.

## Installation
To install QMSan, start by cloning the repository
```console
git clone --recursive https://github.com/Heinzeen/qmsan.git
```
Then compile it using the building script with the appropriate flags
```console
python3 build.py [flags]
```
### List of flags
QMSan supports many execution modes that will be passed as flags during the compilation process.
| Flag | Description |
| --- | ----------- |
|  --afl | Fuzzing mode|
|  --arch | Set target architecture (default x86_64) |
|  --asan | Use address sanitizer |
|  --cc CC | C compiler (default clang-8)|
|  --clean | Clean builded files|
|  --cross CROSS | Cross C compiler for libqasan|
|  --cxx CXX | C++ compiler (default clang++-8)|
|  --debug | Compile debug libqasan|
|  --light_no_lib | Use QMSan's lightwieght NO_LIB mode - track only stores in libraries (msan needed)|
|  --msan | Use memory sanitizer|
|  --mverbose | Make QMSan's output (very) verbose; only inyended for aggressive debugging.|
|  --no_lib | Use QMSan's NO_LIB mode (msan needed)|
|  --taint | Use QMSan's shadow propagation (msan needed)|

By combining the various flags one can achieve different results. See below for intended combinations of flags.

### Docker
To ease deployment, we provide a working dockerfile inside the `Docker/` directory. Navigate and build a docker image with a command similar to
```console
cd Docker
docker build . -t qmsan
```

## Fuzzing with QMSan
QMSan should be used to perform fuzz testing on binary software. To do so, one needs to build an opportunistic detector and have access to an accurate detector. To build QMSan's opportunistic detector, you can use these flags
```console
python3 build.py --msan --no_lib --afl
```
Then, QMSan's accurate detector can be built with 
```console
python3 build.py --msan --taint
```
Alternatively, one can use valgrind as accurate detector.

After creating both an accurate and an opportunistic detector, a custom version of AFL++ is needed for fuzzing. You can download and build it with
```console
git clone https://github.com/Heinzeen/AFL-QMSan.git
cd AFL-QMSan
CFLAGS="-DQMSAN -DQMSAN_FILTERING -DQMSAN_CALLSTACK_EDGES -DQMSAN_CALLSTACK -DQMSAN_EDGES" make clean all
```

Finally, you can perform fuzz testing with a command similar to
```console
QMSAN_PATH=path/to/accurate/detector/qmsan AFL_ENTRYPOINT=main_address  /path/to/AFL-QMSan/afl-fuzz -U -i in/ -o out -m none -- python3 /path/to/opportunistic/detector/qmsan application [application args with @@]
``` 

## Cross compilation
Cross compilation will allow you to test applications from a guest architecture to a different host architecture (i.e. aarch64 software running on x86 machine through QEMU). One simple way to achieve this is to download a cross compiler
```console
sudo apt install gcc-aarch64-linux-gnu
```
Then compile QMSan using the appropriate flags
```console
./build.py --arch arm64 --cross aarch64-linux-gnu-gcc [other flags]
```
At this point you can run your application with QMSan using something like (it only gives relevant results if used with an accurate detector's build)
```console
QEMU_LD_PREFIX=/usr/aarch64-linux-gnu ./qmsan application
```
By setting the `QEMU_LD_PREFIX` env variable it is possible to perform cross-architecture fuzzing using the same command line as before.

## Paper

If you use QMSan for your academic research, use the following citation:

+ Marini, Matteo, Daniele Cono D’Elia, Mathias Payer, and Leonardo Querzoni. "QMSan: Efficiently Detecting Uninitialized Memory Errors During Fuzzing." In Proceedings of the Network and Distributed System Security (NDSS) Symposium 2025. 2025.

Bibtex:

```bibtex
@inproceedings{marini2025qmsan,
  title={QMSan: Efficiently Detecting Uninitialized Memory Errors During Fuzzing},
  author={Marini, Matteo and D’Elia, Daniele Cono and Payer, Mathias and Querzoni, Leonardo and others},
  booktitle={Proceedings of the Network and Distributed System Security (NDSS) Symposium 2025},
  year={2025}
}
```
