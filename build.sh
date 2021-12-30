#!/usr/bin/env bash

rm -rf build install thirdparty

cmake -S . -B build \
-DCMAKE_C_COMPILER=gcc \
-DCMAKE_CXX_COMPILER=g++ \
-DCMAKE_BUILD_TYPE=Release \
-DCMAKE_INSTALL_PREFIX=install \
-DCMAKE_PREFIX_PATH="$(realpath ${PWD}/../hexl/install);$(realpath ${PWD}/../hexl-fpga/install)" \
-DSEAL_BUILD_EXAMPLES=OFF \
-DSEAL_BUILD_TESTS=OFF \
-DSEAL_BUILD_BENCH=OFF \
-DSEAL_BUILD_DEPS=OFF \
-DSEAL_USE_MSGSL=OFF \
-DSEAL_USE_ZLIB=OFF \
-DSEAL_USE_ZSTD=OFF \
-DBUILD_SHARED_LIBS=ON \
-DSEAL_USE_INTEL_HEXL=ON \
-DHEXL_FPGA=ON

cmake --build build -j
cmake --install build
