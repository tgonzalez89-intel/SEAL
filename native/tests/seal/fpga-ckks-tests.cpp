// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/batchencoder.h"
#include "seal/ckks.h"
#include "seal/context.h"
#include "seal/decryptor.h"
#include "seal/encryptor.h"
#include "seal/evaluator.h"
#include "seal/keygenerator.h"
#include "seal/modulus.h"
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <string>
#include "gtest/gtest.h"
#ifdef HEXL_FPGA
#include "hexl-fpga.h"
#endif

using namespace seal;
using namespace std;

namespace sealtest
{
    TEST(EvaluatorTest, FPGACKKSEncryptNaiveMultiplyDecrypt)
    {
        EncryptionParameters parms(scheme_type::ckks);
        {
            // Multiplying two zero vectors
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 30, 30, 30, 30 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            vector<complex<double>> input(slot_size, 0.0);
            vector<complex<double>> output(slot_size);
            const double delta = static_cast<double>(1 << 30);
            encoder.encode(input, context.first_parms_id(), delta, plain);

            encryptor.encrypt(plain, encrypted);
#ifdef HEXL_FPGA
            intel::hexl::set_worksize_DyadicMultiply(1);
#endif
            evaluator.multiply_inplace(encrypted, encrypted);
#ifdef HEXL_FPGA
            intel::hexl::DyadicMultiplyCompleted();
#endif

            // Check correctness of encryption
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

            decryptor.decrypt(encrypted, plainRes);
            encoder.decode(plainRes, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                auto tmp = abs(input[i].real() - output[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
        {
            // Multiplying two random vectors
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 60, 60, 60 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);
            vector<complex<double>> output(slot_size);
            const double delta = static_cast<double>(1ULL << 40);

            int data_bound = (1 << 10);
            srand(static_cast<unsigned>(time(NULL)));

            for (int round = 0; round < 100; round++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * input2[i];
                }
                encoder.encode(input1, context.first_parms_id(), delta, plain1);
                encoder.encode(input2, context.first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);
#ifdef HEXL_FPGA
                intel::hexl::set_worksize_DyadicMultiply(1);
#endif
                evaluator.multiply_inplace(encrypted1, encrypted2);
#ifdef HEXL_FPGA
                intel::hexl::DyadicMultiplyCompleted();
#endif

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Multiplying two random vectors
            size_t slot_size = 16;
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 60, 60, 60 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);
            vector<complex<double>> output(slot_size);
            const double delta = static_cast<double>(1ULL << 40);

            int data_bound = (1 << 10);
            srand(static_cast<unsigned>(time(NULL)));

            for (int round = 0; round < 100; round++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * input2[i];
                }
                encoder.encode(input1, context.first_parms_id(), delta, plain1);
                encoder.encode(input2, context.first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);
#ifdef HEXL_FPGA
                intel::hexl::set_worksize_DyadicMultiply(1);
#endif
                evaluator.multiply_inplace(encrypted1, encrypted2);
#ifdef HEXL_FPGA
                intel::hexl::DyadicMultiplyCompleted();
#endif

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
    }

    TEST(EvaluatorTest, FPGACKKSEncryptMultiplyRelinDecrypt)
    {
        EncryptionParameters parms(scheme_type::ckks);
        {
            // Multiplying two random vectors 50 times
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 60, 60, 60 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            RelinKeys rlk;
            keygen.create_relin_keys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Ciphertext encryptedRes;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);
            int data_bound = 1 << 10;

            for (int round = 0; round < 50; round++)
            {
                srand(static_cast<unsigned>(time(NULL)));
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * input2[i];
                }

                vector<complex<double>> output(slot_size);
                const double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input1, context.first_parms_id(), delta, plain1);
                encoder.encode(input2, context.first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());
                // Check correctness of encryption
                ASSERT_TRUE(encrypted2.parms_id() == context.first_parms_id());

#ifdef HEXL_FPGA
                intel::hexl::set_worksize_DyadicMultiply(1);
#endif
                evaluator.multiply_inplace(encrypted1, encrypted2);
#ifdef HEXL_FPGA
                intel::hexl::DyadicMultiplyCompleted();
#endif
                evaluator.relinearize_inplace(encrypted1, rlk);

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Multiplying two random vectors 50 times
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 60, 30, 30, 30 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            RelinKeys rlk;
            keygen.create_relin_keys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Ciphertext encryptedRes;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);
            int data_bound = 1 << 10;

            for (int round = 0; round < 50; round++)
            {
                srand(static_cast<unsigned>(time(NULL)));
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * input2[i];
                }

                vector<complex<double>> output(slot_size);
                const double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input1, context.first_parms_id(), delta, plain1);
                encoder.encode(input2, context.first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());
                // Check correctness of encryption
                ASSERT_TRUE(encrypted2.parms_id() == context.first_parms_id());

#ifdef HEXL_FPGA
                intel::hexl::set_worksize_DyadicMultiply(1);
#endif
                evaluator.multiply_inplace(encrypted1, encrypted2);
#ifdef HEXL_FPGA
                intel::hexl::DyadicMultiplyCompleted();
#endif
                evaluator.relinearize_inplace(encrypted1, rlk);

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Multiplying two random vectors 50 times
            size_t slot_size = 2;
            parms.set_poly_modulus_degree(8);
            parms.set_coeff_modulus(CoeffModulus::Create(8, { 60, 30, 30, 30 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            RelinKeys rlk;
            keygen.create_relin_keys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Ciphertext encryptedRes;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);
            vector<complex<double>> output(slot_size);
            int data_bound = 1 << 10;
            const double delta = static_cast<double>(1ULL << 40);

            for (int round = 0; round < 50; round++)
            {
                srand(static_cast<unsigned>(time(NULL)));
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * input2[i];
                }

                encoder.encode(input1, context.first_parms_id(), delta, plain1);
                encoder.encode(input2, context.first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());
                // Check correctness of encryption
                ASSERT_TRUE(encrypted2.parms_id() == context.first_parms_id());

#ifdef HEXL_FPGA
                intel::hexl::set_worksize_DyadicMultiply(1);
#endif
                evaluator.multiply_inplace(encrypted1, encrypted2);
#ifdef HEXL_FPGA
                intel::hexl::DyadicMultiplyCompleted();
#endif
                // Evaluator.relinearize_inplace(encrypted1, rlk);

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
    }

    TEST(EvaluatorTest, FPGACKKSEncryptSquareRelinDecrypt)
    {
        EncryptionParameters parms(scheme_type::ckks);
        {
            // Squaring two random vectors 100 times
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 60, 60, 60 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            RelinKeys rlk;
            keygen.create_relin_keys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            vector<complex<double>> input(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);

            int data_bound = 1 << 7;
            srand(static_cast<unsigned>(time(NULL)));

            for (int round = 0; round < 100; round++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input[i] * input[i];
                }

                vector<complex<double>> output(slot_size);
                const double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input, context.first_parms_id(), delta, plain);

                encryptor.encrypt(plain, encrypted);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

                // Evaluator.square_inplace(encrypted);
#ifdef HEXL_FPGA
                intel::hexl::set_worksize_DyadicMultiply(1);
#endif
                evaluator.multiply_inplace(encrypted, encrypted);
#ifdef HEXL_FPGA
                intel::hexl::DyadicMultiplyCompleted();
#endif
                evaluator.relinearize_inplace(encrypted, rlk);

                decryptor.decrypt(encrypted, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Squaring two random vectors 100 times
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 60, 30, 30, 30 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            RelinKeys rlk;
            keygen.create_relin_keys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            vector<complex<double>> input(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);

            int data_bound = 1 << 7;
            srand(static_cast<unsigned>(time(NULL)));

            for (int round = 0; round < 100; round++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input[i] * input[i];
                }

                vector<complex<double>> output(slot_size);
                const double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input, context.first_parms_id(), delta, plain);

                encryptor.encrypt(plain, encrypted);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

                // Evaluator.square_inplace(encrypted);
#ifdef HEXL_FPGA
                intel::hexl::set_worksize_DyadicMultiply(1);
#endif
                evaluator.multiply_inplace(encrypted, encrypted);
#ifdef HEXL_FPGA
                intel::hexl::DyadicMultiplyCompleted();
#endif
                evaluator.relinearize_inplace(encrypted, rlk);

                decryptor.decrypt(encrypted, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Squaring two random vectors 100 times
            size_t slot_size = 16;
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 60, 30, 30, 30 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            RelinKeys rlk;
            keygen.create_relin_keys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            vector<complex<double>> input(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);

            int data_bound = 1 << 7;
            srand(static_cast<unsigned>(time(NULL)));

            for (int round = 0; round < 100; round++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input[i] * input[i];
                }

                vector<complex<double>> output(slot_size);
                const double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input, context.first_parms_id(), delta, plain);

                encryptor.encrypt(plain, encrypted);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

                // Evaluator.square_inplace(encrypted);
#ifdef HEXL_FPGA
                intel::hexl::set_worksize_DyadicMultiply(1);
#endif
                evaluator.multiply_inplace(encrypted, encrypted);
#ifdef HEXL_FPGA
                intel::hexl::DyadicMultiplyCompleted();
#endif
                evaluator.relinearize_inplace(encrypted, rlk);

                decryptor.decrypt(encrypted, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
    }

    TEST(EvaluatorTest, FPGACKKSEncryptMultiplyRelinRescaleDecrypt)
    {
        EncryptionParameters parms(scheme_type::ckks);
        {
            // Multiplying two random vectors 100 times
            size_t slot_size = 64;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 30, 30, 30, 30, 30, 30 }));

            SEALContext context(parms, true, sec_level_type::none);
            auto next_parms_id = context.first_context_data()->next_context_data()->parms_id();
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            RelinKeys rlk;
            keygen.create_relin_keys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Ciphertext encryptedRes;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);

            for (int round = 0; round < 100; round++)
            {
                int data_bound = 1 << 7;
                srand(static_cast<unsigned>(time(NULL)));
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * input2[i];
                }

                vector<complex<double>> output(slot_size);
                double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input1, context.first_parms_id(), delta, plain1);
                encoder.encode(input2, context.first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());
                // Check correctness of encryption
                ASSERT_TRUE(encrypted2.parms_id() == context.first_parms_id());

#ifdef HEXL_FPGA
                intel::hexl::set_worksize_DyadicMultiply(1);
#endif
                evaluator.multiply_inplace(encrypted1, encrypted2);
#ifdef HEXL_FPGA
                intel::hexl::DyadicMultiplyCompleted();
#endif
                evaluator.relinearize_inplace(encrypted1, rlk);
                evaluator.rescale_to_next_inplace(encrypted1);

                // Check correctness of modulus switching
                ASSERT_TRUE(encrypted1.parms_id() == next_parms_id);

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Multiplying two random vectors 100 times
            size_t slot_size = 16;
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, { 30, 30, 30, 30, 30 }));

            SEALContext context(parms, true, sec_level_type::none);
            auto next_parms_id = context.first_context_data()->next_context_data()->parms_id();
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            RelinKeys rlk;
            keygen.create_relin_keys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Ciphertext encryptedRes;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);

            for (int round = 0; round < 100; round++)
            {
                int data_bound = 1 << 7;
                srand(static_cast<unsigned>(time(NULL)));
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * input2[i];
                }

                vector<complex<double>> output(slot_size);
                double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input1, context.first_parms_id(), delta, plain1);
                encoder.encode(input2, context.first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());
                // Check correctness of encryption
                ASSERT_TRUE(encrypted2.parms_id() == context.first_parms_id());

#ifdef HEXL_FPGA
                intel::hexl::set_worksize_DyadicMultiply(1);
#endif
                evaluator.multiply_inplace(encrypted1, encrypted2);
#ifdef HEXL_FPGA
                intel::hexl::DyadicMultiplyCompleted();
#endif
                evaluator.relinearize_inplace(encrypted1, rlk);
                evaluator.rescale_to_next_inplace(encrypted1);

                // Check correctness of modulus switching
                ASSERT_TRUE(encrypted1.parms_id() == next_parms_id);

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Multiplying two random vectors 100 times
            size_t slot_size = 16;
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, { 60, 60, 60, 60, 60 }));

            SEALContext context(parms, true, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            RelinKeys rlk;
            keygen.create_relin_keys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Ciphertext encryptedRes;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);

            for (int round = 0; round < 100; round++)
            {
                int data_bound = 1 << 7;
                srand(static_cast<unsigned>(time(NULL)));
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * input2[i] * input2[i];
                }

                vector<complex<double>> output(slot_size);
                double delta = static_cast<double>(1ULL << 60);
                encoder.encode(input1, context.first_parms_id(), delta, plain1);
                encoder.encode(input2, context.first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());
                // Check correctness of encryption
                ASSERT_TRUE(encrypted2.parms_id() == context.first_parms_id());

#ifdef HEXL_FPGA
                intel::hexl::set_worksize_DyadicMultiply(1);
#endif
                evaluator.multiply_inplace(encrypted1, encrypted2);
#ifdef HEXL_FPGA
                intel::hexl::DyadicMultiplyCompleted();
#endif
                evaluator.relinearize_inplace(encrypted1, rlk);
#ifdef HEXL_FPGA
                intel::hexl::set_worksize_DyadicMultiply(1);
#endif
                evaluator.multiply_inplace(encrypted1, encrypted2);
#ifdef HEXL_FPGA
                intel::hexl::DyadicMultiplyCompleted();
#endif
                evaluator.relinearize_inplace(encrypted1, rlk);

                // Scale down by two levels
                auto target_parms = context.first_context_data()->next_context_data()->next_context_data()->parms_id();
                evaluator.rescale_to_inplace(encrypted1, target_parms);

                // Check correctness of modulus switching
                ASSERT_TRUE(encrypted1.parms_id() == target_parms);

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }

            // Test with inverted order: rescale then relin
            for (int round = 0; round < 100; round++)
            {
                int data_bound = 1 << 7;
                srand(static_cast<unsigned>(time(NULL)));
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * input2[i] * input2[i];
                }

                vector<complex<double>> output(slot_size);
                double delta = static_cast<double>(1ULL << 50);
                encoder.encode(input1, context.first_parms_id(), delta, plain1);
                encoder.encode(input2, context.first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());
                // Check correctness of encryption
                ASSERT_TRUE(encrypted2.parms_id() == context.first_parms_id());

#ifdef HEXL_FPGA
                intel::hexl::set_worksize_DyadicMultiply(1);
#endif
                evaluator.multiply_inplace(encrypted1, encrypted2);
#ifdef HEXL_FPGA
                intel::hexl::DyadicMultiplyCompleted();
#endif
                evaluator.relinearize_inplace(encrypted1, rlk);
#ifdef HEXL_FPGA
                intel::hexl::set_worksize_DyadicMultiply(1);
#endif
                evaluator.multiply_inplace(encrypted1, encrypted2);
#ifdef HEXL_FPGA
                intel::hexl::DyadicMultiplyCompleted();
#endif

                // Scale down by two levels
                auto target_parms = context.first_context_data()->next_context_data()->next_context_data()->parms_id();
                evaluator.rescale_to_inplace(encrypted1, target_parms);

                // Relinearize now
                evaluator.relinearize_inplace(encrypted1, rlk);

                // Check correctness of modulus switching
                ASSERT_TRUE(encrypted1.parms_id() == target_parms);

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
    }

    TEST(EvaluatorTest, FPGACKKSEncryptSquareRelinRescaleDecrypt)
    {
        EncryptionParameters parms(scheme_type::ckks);
        {
            // Squaring two random vectors 100 times
            size_t slot_size = 64;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 50, 50, 50 }));

            SEALContext context(parms, true, sec_level_type::none);
            auto next_parms_id = context.first_context_data()->next_context_data()->parms_id();
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            RelinKeys rlk;
            keygen.create_relin_keys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            vector<complex<double>> input(slot_size, 0.0);
            vector<complex<double>> output(slot_size);
            vector<complex<double>> expected(slot_size, 0.0);
            int data_bound = 1 << 8;

            for (int round = 0; round < 100; round++)
            {
                srand(static_cast<unsigned>(time(NULL)));
                for (size_t i = 0; i < slot_size; i++)
                {
                    input[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input[i] * input[i];
                }

                double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input, context.first_parms_id(), delta, plain);

                encryptor.encrypt(plain, encrypted);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

#ifdef HEXL_FPGA
                intel::hexl::set_worksize_DyadicMultiply(1);
#endif
                evaluator.square_inplace(encrypted);
#ifdef HEXL_FPGA
                intel::hexl::DyadicMultiplyCompleted();
#endif
                evaluator.relinearize_inplace(encrypted, rlk);
                evaluator.rescale_to_next_inplace(encrypted);

                // Check correctness of modulus switching
                ASSERT_TRUE(encrypted.parms_id() == next_parms_id);

                decryptor.decrypt(encrypted, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Squaring two random vectors 100 times
            size_t slot_size = 16;
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, { 50, 50, 50 }));

            SEALContext context(parms, true, sec_level_type::none);
            auto next_parms_id = context.first_context_data()->next_context_data()->parms_id();
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            RelinKeys rlk;
            keygen.create_relin_keys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            vector<complex<double>> input(slot_size, 0.0);
            vector<complex<double>> output(slot_size);
            vector<complex<double>> expected(slot_size, 0.0);
            int data_bound = 1 << 8;

            for (int round = 0; round < 100; round++)
            {
                srand(static_cast<unsigned>(time(NULL)));
                for (size_t i = 0; i < slot_size; i++)
                {
                    input[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input[i] * input[i];
                }

                double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input, context.first_parms_id(), delta, plain);

                encryptor.encrypt(plain, encrypted);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

#ifdef HEXL_FPGA
                intel::hexl::set_worksize_DyadicMultiply(1);
#endif
                evaluator.square_inplace(encrypted);
#ifdef HEXL_FPGA
                intel::hexl::DyadicMultiplyCompleted();
#endif
                evaluator.relinearize_inplace(encrypted, rlk);
                evaluator.rescale_to_next_inplace(encrypted);

                // Check correctness of modulus switching
                ASSERT_TRUE(encrypted.parms_id() == next_parms_id);

                decryptor.decrypt(encrypted, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
    }

    TEST(EvaluatorTest, FPGACKKSEncryptRotateDecrypt)
    {
        EncryptionParameters parms(scheme_type::ckks);
        {
            // Maximal number of slots
            size_t slot_size = 4;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 40, 40, 40, 40 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            GaloisKeys glk;
            keygen.create_galois_keys(glk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());
            CKKSEncoder encoder(context);
            const double delta = static_cast<double>(1ULL << 30);

            Ciphertext encrypted;
            Plaintext plain;

            vector<complex<double>> input{ complex<double>(1, 1), complex<double>(2, 2), complex<double>(3, 3),
                                           complex<double>(4, 4) };
            input.resize(slot_size);

            vector<complex<double>> output(slot_size, 0);

            encoder.encode(input, context.first_parms_id(), delta, plain);
            int shift = 1;
            encryptor.encrypt(plain, encrypted);
            evaluator.rotate_vector_inplace(encrypted, shift, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(input[(i + static_cast<size_t>(shift)) % slot_size].real(), round(output[i].real()));
                ASSERT_EQ(input[(i + static_cast<size_t>(shift)) % slot_size].imag(), round(output[i].imag()));
            }

            encoder.encode(input, context.first_parms_id(), delta, plain);
            shift = 2;
            encryptor.encrypt(plain, encrypted);
            evaluator.rotate_vector_inplace(encrypted, shift, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(input[(i + static_cast<size_t>(shift)) % slot_size].real(), round(output[i].real()));
                ASSERT_EQ(input[(i + static_cast<size_t>(shift)) % slot_size].imag(), round(output[i].imag()));
            }

            encoder.encode(input, context.first_parms_id(), delta, plain);
            shift = 3;
            encryptor.encrypt(plain, encrypted);
            evaluator.rotate_vector_inplace(encrypted, shift, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(input[(i + static_cast<size_t>(shift)) % slot_size].real(), round(output[i].real()));
                ASSERT_EQ(input[(i + static_cast<size_t>(shift)) % slot_size].imag(), round(output[i].imag()));
            }

            encoder.encode(input, context.first_parms_id(), delta, plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.complex_conjugate_inplace(encrypted, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(input[i].real(), round(output[i].real()));
                ASSERT_EQ(-input[i].imag(), round(output[i].imag()));
            }
        }
        {
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40, 40 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            GaloisKeys glk;
            keygen.create_galois_keys(glk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());
            CKKSEncoder encoder(context);
            const double delta = static_cast<double>(1ULL << 30);

            Ciphertext encrypted;
            Plaintext plain;

            vector<complex<double>> input{ complex<double>(1, 1), complex<double>(2, 2), complex<double>(3, 3),
                                           complex<double>(4, 4) };
            input.resize(slot_size);

            vector<complex<double>> output(slot_size, 0);

            encoder.encode(input, context.first_parms_id(), delta, plain);
            int shift = 1;
            encryptor.encrypt(plain, encrypted);
            evaluator.rotate_vector_inplace(encrypted, shift, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < input.size(); i++)
            {
                ASSERT_EQ(round(input[(i + static_cast<size_t>(shift)) % slot_size].real()), round(output[i].real()));
                ASSERT_EQ(round(input[(i + static_cast<size_t>(shift)) % slot_size].imag()), round(output[i].imag()));
            }

            encoder.encode(input, context.first_parms_id(), delta, plain);
            shift = 2;
            encryptor.encrypt(plain, encrypted);
            evaluator.rotate_vector_inplace(encrypted, shift, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(round(input[(i + static_cast<size_t>(shift)) % slot_size].real()), round(output[i].real()));
                ASSERT_EQ(round(input[(i + static_cast<size_t>(shift)) % slot_size].imag()), round(output[i].imag()));
            }

            encoder.encode(input, context.first_parms_id(), delta, plain);
            shift = 3;
            encryptor.encrypt(plain, encrypted);
            evaluator.rotate_vector_inplace(encrypted, shift, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(round(input[(i + static_cast<size_t>(shift)) % slot_size].real()), round(output[i].real()));
                ASSERT_EQ(round(input[(i + static_cast<size_t>(shift)) % slot_size].imag()), round(output[i].imag()));
            }

            encoder.encode(input, context.first_parms_id(), delta, plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.complex_conjugate_inplace(encrypted, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(round(input[i].real()), round(output[i].real()));
                ASSERT_EQ(round(-input[i].imag()), round(output[i].imag()));
            }
        }
    }

    TEST(EvaluatorTest, FPGACKKSEncryptRescaleRotateDecrypt)
    {
        EncryptionParameters parms(scheme_type::ckks);
        {
            // Maximal number of slots
            size_t slot_size = 4;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 40, 40, 40, 40 }));

            SEALContext context(parms, true, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            GaloisKeys glk;
            keygen.create_galois_keys(glk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());
            CKKSEncoder encoder(context);
            const double delta = pow(2.0, 70);

            Ciphertext encrypted;
            Plaintext plain;

            vector<complex<double>> input{ complex<double>(1, 1), complex<double>(2, 2), complex<double>(3, 3),
                                           complex<double>(4, 4) };
            input.resize(slot_size);

            vector<complex<double>> output(slot_size, 0);

            encoder.encode(input, context.first_parms_id(), delta, plain);
            int shift = 1;
            encryptor.encrypt(plain, encrypted);
            evaluator.rescale_to_next_inplace(encrypted);
            evaluator.rotate_vector_inplace(encrypted, shift, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(input[(i + static_cast<size_t>(shift)) % slot_size].real(), round(output[i].real()));
                ASSERT_EQ(input[(i + static_cast<size_t>(shift)) % slot_size].imag(), round(output[i].imag()));
            }

            encoder.encode(input, context.first_parms_id(), delta, plain);
            shift = 2;
            encryptor.encrypt(plain, encrypted);
            evaluator.rescale_to_next_inplace(encrypted);
            evaluator.rotate_vector_inplace(encrypted, shift, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(input[(i + static_cast<size_t>(shift)) % slot_size].real(), round(output[i].real()));
                ASSERT_EQ(input[(i + static_cast<size_t>(shift)) % slot_size].imag(), round(output[i].imag()));
            }

            encoder.encode(input, context.first_parms_id(), delta, plain);
            shift = 3;
            encryptor.encrypt(plain, encrypted);
            evaluator.rescale_to_next_inplace(encrypted);
            evaluator.rotate_vector_inplace(encrypted, shift, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(input[(i + static_cast<size_t>(shift)) % slot_size].real(), round(output[i].real()));
                ASSERT_EQ(input[(i + static_cast<size_t>(shift)) % slot_size].imag(), round(output[i].imag()));
            }

            encoder.encode(input, context.first_parms_id(), delta, plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.rescale_to_next_inplace(encrypted);
            evaluator.complex_conjugate_inplace(encrypted, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(input[i].real(), round(output[i].real()));
                ASSERT_EQ(-input[i].imag(), round(output[i].imag()));
            }
        }
        {
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40, 40 }));

            SEALContext context(parms, true, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            GaloisKeys glk;
            keygen.create_galois_keys(glk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());
            CKKSEncoder encoder(context);
            const double delta = pow(2, 70);

            Ciphertext encrypted;
            Plaintext plain;

            vector<complex<double>> input{ complex<double>(1, 1), complex<double>(2, 2), complex<double>(3, 3),
                                           complex<double>(4, 4) };
            input.resize(slot_size);

            vector<complex<double>> output(slot_size, 0);

            encoder.encode(input, context.first_parms_id(), delta, plain);
            int shift = 1;
            encryptor.encrypt(plain, encrypted);
            evaluator.rescale_to_next_inplace(encrypted);
            evaluator.rotate_vector_inplace(encrypted, shift, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(round(input[(i + static_cast<size_t>(shift)) % slot_size].real()), round(output[i].real()));
                ASSERT_EQ(round(input[(i + static_cast<size_t>(shift)) % slot_size].imag()), round(output[i].imag()));
            }

            encoder.encode(input, context.first_parms_id(), delta, plain);
            shift = 2;
            encryptor.encrypt(plain, encrypted);
            evaluator.rescale_to_next_inplace(encrypted);
            evaluator.rotate_vector_inplace(encrypted, shift, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(round(input[(i + static_cast<size_t>(shift)) % slot_size].real()), round(output[i].real()));
                ASSERT_EQ(round(input[(i + static_cast<size_t>(shift)) % slot_size].imag()), round(output[i].imag()));
            }

            encoder.encode(input, context.first_parms_id(), delta, plain);
            shift = 3;
            encryptor.encrypt(plain, encrypted);
            evaluator.rescale_to_next_inplace(encrypted);
            evaluator.rotate_vector_inplace(encrypted, shift, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(round(input[(i + static_cast<size_t>(shift)) % slot_size].real()), round(output[i].real()));
                ASSERT_EQ(round(input[(i + static_cast<size_t>(shift)) % slot_size].imag()), round(output[i].imag()));
            }

            encoder.encode(input, context.first_parms_id(), delta, plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.rescale_to_next_inplace(encrypted);
            evaluator.complex_conjugate_inplace(encrypted, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(round(input[i].real()), round(output[i].real()));
                ASSERT_EQ(round(-input[i].imag()), round(output[i].imag()));
            }
        }
    }
} // namespace sealtest
