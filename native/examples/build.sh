#!/usr/bin/env bash

rm -rf build

cmake -S . -B build \
-DCMAKE_C_COMPILER=gcc \
-DCMAKE_CXX_COMPILER=g++ \
-DCMAKE_BUILD_TYPE=Release \
-DCMAKE_PREFIX_PATH="$(realpath ${PWD}/../../install);$(realpath ${PWD}/../../../hexl/install);$(realpath ${PWD}/../../../hexl-fpga/install)" \
-DHEXL_FPGA=ON

cmake --build build -j
