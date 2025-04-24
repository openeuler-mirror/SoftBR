# SoftBR
A software-only implementation of architechture neutral branch tracing tool.

## Prerequisites
Install necessary libraries:

`libunwind`:
```
sudo yum install libunwind libunwind-devel
```


`Dynamorio`:
Download the 10.0 version and put it under `third_party` with name `Dynamorio`.
```
cd third_party
wget https://github.com/DynamoRIO/dynamorio/releases/download/release_10.0.0/DynamoRIO-AArch64-Linux-10.0.0.tar.gz
tar -xf DynamoRIO-AArch64-Linux-10.0.0.tar.gz
mv DynamoRIO-AArch64-Linux-10.0.0 DynamoRIO
```


## Compile
you should use BiSheng compiler to compile profiler.
```
export CC=/bisheng/bin/clang
export CXX=/bisheng/bin/clang++
mkdir build
cd build
cmake .. && make -j
```
## How to run
There are 2 ways to use BR:
1. use the profiler with `LD_PRELOAD`

2. Directly link the libprofiler.so to your program.just like `-lprofiler`

## profile file

The sampled content is in the file `perf_data.br`.

```
PERF_RECORD_MMP2 1234/1234: [0xaaaaaad1c000(0x654000) @ oxdc000 fd:04 1234 0] r-xp redis
PERF_RECORD_MMP2 XXX
PERF_RECORD_MMP2 XXX
3469800 // pid
            aaaaaad5e0f0    //stack
            aaaaaada762c
            ...
            aaaaaadc98ac
 0xaaaaaad5e0f0/0xaaaaaad5e0b0/p/-/-/1 ...  0xaaaaaad5e0f0/0xaaaaaad5e0b0/p/-/-/1   // branch record
 ```