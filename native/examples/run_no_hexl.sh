#!/usr/bin/env bash

cd build/bin

# Bench

./fpga-ckks-example -mode=bench -poly_modulus_degree=4096
./fpga-ckks-example -mode=bench -poly_modulus_degree=8192
./fpga-ckks-example -mode=bench -poly_modulus_degree=16384

# Test

./fpga-ckks-example -mode=test -poly_modulus_degree=4096 -coeff_mod_bit_sizes=27,27,27,27 -scale_bit_size=27 -security_lvl=128
./fpga-ckks-example -mode=test -poly_modulus_degree=8192 -coeff_mod_bit_sizes=60,40,40,60 -scale_bit_size=40 -security_lvl=128
./fpga-ckks-example -mode=test -poly_modulus_degree=16384 -coeff_mod_bit_sizes=60,40,40,60 -scale_bit_size=40 -security_lvl=128

cd ..
