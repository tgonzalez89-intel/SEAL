#!/usr/bin/env bash

cd build/bin

export RUN_CHOICE=1
export FPGA_ENABLE_NTT=0
export FPGA_ENABLE_INTT=0
export FPGA_ENABLE_DYADIC_MULTIPLY=1
export BATCH_SIZE_DYADIC_MULTIPLY=1
export COEFF_SIZE=32768
export MODULUS_SIZE=16
export FPGA_DEBUG=0

# Bench

export FPGA_ENABLE_DYADIC_MULTIPLY=1

export COEFF_SIZE=4096
export MODULUS_SIZE=3
./fpga-ckks-example -mode=bench -poly_modulus_degree=4096
export COEFF_SIZE=8192
export MODULUS_SIZE=5
./fpga-ckks-example -mode=bench -poly_modulus_degree=8192
export COEFF_SIZE=16384
export MODULUS_SIZE=9
./fpga-ckks-example -mode=bench -poly_modulus_degree=16384

export FPGA_ENABLE_DYADIC_MULTIPLY=0

./fpga-ckks-example -mode=bench -poly_modulus_degree=4096
./fpga-ckks-example -mode=bench -poly_modulus_degree=8192
./fpga-ckks-example -mode=bench -poly_modulus_degree=16384

# Test

export FPGA_ENABLE_DYADIC_MULTIPLY=1

export COEFF_SIZE=4096
export MODULUS_SIZE=3
./fpga-ckks-example -mode=test -poly_modulus_degree=4096 -coeff_mod_bit_sizes=27,27,27,27 -scale_bit_size=27 -security_lvl=128
export COEFF_SIZE=8192
export MODULUS_SIZE=4
./fpga-ckks-example -mode=test -poly_modulus_degree=8192 -coeff_mod_bit_sizes=60,40,40,60 -scale_bit_size=40 -security_lvl=128
export COEFF_SIZE=16384
export MODULUS_SIZE=4
./fpga-ckks-example -mode=test -poly_modulus_degree=16384 -coeff_mod_bit_sizes=60,40,40,60 -scale_bit_size=40 -security_lvl=128

export FPGA_ENABLE_DYADIC_MULTIPLY=0

./fpga-ckks-example -mode=test -poly_modulus_degree=4096 -coeff_mod_bit_sizes=27,27,27,27 -scale_bit_size=27 -security_lvl=128
./fpga-ckks-example -mode=test -poly_modulus_degree=8192 -coeff_mod_bit_sizes=60,40,40,60 -scale_bit_size=40 -security_lvl=128
./fpga-ckks-example -mode=test -poly_modulus_degree=16384 -coeff_mod_bit_sizes=60,40,40,60 -scale_bit_size=40 -security_lvl=128

cd ..
