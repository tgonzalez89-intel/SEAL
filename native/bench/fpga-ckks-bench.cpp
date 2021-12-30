// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/seal.h"
#include "seal/util/rlwe.h"
#include "bench.h"
#ifdef HEXL_FPGA
#include "hexl-fpga.h"
#endif

using namespace benchmark;
using namespace sealbench;
using namespace seal;
using namespace std;

/**
This file defines benchmarks for CKKS-specific HE primitives.
*/

namespace sealbench
{
    void bm_fpga_ckks_mul_ct(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> &ct = bm_env->ct();
        double scale = bm_env->safe_scale();
        for (auto _ : state)
        {
            state.PauseTiming();
            bm_env->randomize_ct_ckks(ct[0]);
            ct[0].scale() = scale;
            bm_env->randomize_ct_ckks(ct[1]);
            ct[1].scale() = scale;

            state.ResumeTiming();
#ifdef HEXL_FPGA
            intel::hexl::set_worksize_DyadicMultiply(1);
#endif
            bm_env->evaluator()->multiply(ct[0], ct[1], ct[2]);
#ifdef HEXL_FPGA
            intel::hexl::DyadicMultiplyCompleted();
#endif
        }
    }

    void bm_fpga_ckks_square(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> &ct = bm_env->ct();
        double scale = bm_env->safe_scale();
        for (auto _ : state)
        {
            state.PauseTiming();
            bm_env->randomize_ct_ckks(ct[0]);
            ct[0].scale() = scale;
            bm_env->randomize_ct_ckks(ct[1]);
            ct[1].scale() = scale;

            state.ResumeTiming();
#ifdef HEXL_FPGA
            intel::hexl::set_worksize_DyadicMultiply(1);
#endif
            bm_env->evaluator()->square(ct[0], ct[2]);
#ifdef HEXL_FPGA
            intel::hexl::DyadicMultiplyCompleted();
#endif
        }
    }

    void bm_fpga_ckks_relin_inplace(State &state, shared_ptr<BMEnv> bm_env)
    {
        Ciphertext ct;
        for (auto _ : state)
        {
            state.PauseTiming();
            ct.resize(bm_env->context(), size_t(3));
            bm_env->randomize_ct_ckks(ct);

            state.ResumeTiming();
            bm_env->evaluator()->relinearize_inplace(ct, bm_env->rlk());
        }
    }

    void bm_fpga_ckks_rotate(State &state, shared_ptr<BMEnv> bm_env)
    {
        vector<Ciphertext> &ct = bm_env->ct();
        for (auto _ : state)
        {
            state.PauseTiming();
            bm_env->randomize_ct_ckks(ct[0]);

            state.ResumeTiming();
            bm_env->evaluator()->rotate_vector(ct[0], 1, bm_env->glk(), ct[2]);
        }
    }
} // namespace sealbench
