#!/usr/bin/env bash

rm -rf build install thirdparty

cmake -S . -B build \
-DCMAKE_C_COMPILER=gcc \
-DCMAKE_CXX_COMPILER=g++ \
-DCMAKE_BUILD_TYPE=Release \
-DCMAKE_INSTALL_PREFIX=install \
-DCMAKE_PREFIX_PATH="$(realpath ${PWD}/../hexl/install.disable);$(realpath ${PWD}/../hexl-fpga/install.disable)" \
-DSEAL_BUILD_EXAMPLES=ON \
-DSEAL_BUILD_TESTS=OFF \
-DSEAL_BUILD_BENCH=OFF \
-DSEAL_BUILD_DEPS=ON \
-DSEAL_USE_MSGSL=OFF \
-DSEAL_USE_ZLIB=OFF \
-DSEAL_USE_ZSTD=OFF \
-DBUILD_SHARED_LIBS=ON \
-DSEAL_USE_INTEL_HEXL=ON \
-DSEAL_USE_INTEL_HEXL_FPGA=OFF \
-DHEXL_EXPERIMENTAL=ON \
-DHEXL_DUMP_JSON=OFF

cmake --build build -j
#cmake --install build

cd build/bin
ln -s $(realpath ${PWD}/../../../hexl-fpga/install/fpga/hexl_fpga.aocx)
cd ../..
