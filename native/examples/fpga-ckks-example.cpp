/*
How to run:

# Use 1 for emulation, 2 for FPGA (default=2)
export RUN_CHOICE=1
# Enable/disable NTT in FPGA (default=1)
export FPGA_ENABLE_NTT=0
# Enable/disable INTT in FPGA (default=1)
export FPGA_ENABLE_INTT=0
# Enable/disable dyadic multiply in FPGA (default=1)
export FPGA_ENABLE_DYADIC_MULTIPLY=1
# Set dyadic multiply batch size (default=1)
export BATCH_SIZE_DYADIC_MULTIPLY=1
# Set the poly modulus degree (default=16384)
export COEFF_SIZE=16384
# Set the modulus size (default=14)
export MODULUS_SIZE=14
# Set level of debug info (0-2) (default=0)
export FPGA_DEBUG=1

./key-switch-test-and-bench <params...>

# Note: .aocx files containing the bitstreams must be in the same directory as the executable.
*/

#include "seal/seal.h"
#include <algorithm>
#include <chrono>
#include <iostream>
#include <sstream>
#include <vector>
#include "gflags/gflags.h"
#ifdef HEXL_FPGA
#include "hexl-fpga.h"
#endif

using namespace seal;

enum class mode_type
{
    test,
    bench
};

/*
Helper function: Prints the parameters in a SEALContext.
*/
void print_parameters(const mode_type mode, const SEALContext &context, const double scale, const unsigned bench_time)
{
    auto &context_data = *context.key_context_data();

    std::cout << "\n/\n";
    std::cout << "| Parameters :\n";

    /*
    Print the mode.
    */
    std::string mode_name;
    switch (mode)
    {
    case mode_type::test:
        mode_name = "test";
        break;
    case mode_type::bench:
        mode_name = "benchmark";
        break;
    default:
        throw std::invalid_argument("Unsupported mode.");
    }
    std::cout << "|   mode: " << mode_name << '\n';

    /*
    Print the scheme.
    */
    std::string scheme_name;
    switch (context_data.parms().scheme())
    {
    case seal::scheme_type::bfv:
        scheme_name = "BFV";
        break;
    case seal::scheme_type::ckks:
        scheme_name = "CKKS";
        break;
    default:
        throw std::invalid_argument("Unsupported scheme.");
    }
    std::cout << "|   scheme: " << scheme_name << '\n';

    /*
    Print the poly_modulus_degree.
    */
    std::cout << "|   poly_modulus_degree: " << context_data.parms().poly_modulus_degree() << '\n';

    /*
    Print the size of the true (product) coefficient modulus.
    */
    std::cout << "|   coeff_modulus size: ";
    std::cout << context_data.total_coeff_modulus_bit_count() << " (";
    auto coeff_modulus = context_data.parms().coeff_modulus();
    std::size_t coeff_modulus_size = coeff_modulus.size();
    for (std::size_t i = 0; i < coeff_modulus_size - 1; i++)
    {
        std::cout << coeff_modulus[i].bit_count() << " + ";
    }
    std::cout << coeff_modulus.back().bit_count();
    std::cout << ") bits (" << coeff_modulus.size() << " elements)\n";

    /*
    For the CKKS scheme print the scale parameter.
    */
    if (context_data.parms().scheme() == seal::scheme_type::ckks)
    {
        std::cout << "|   scale: " << static_cast<long>(scale) << '\n';
    }

    /*
    For the BFV scheme print the plain_modulus parameter.
    */
    if (context_data.parms().scheme() == seal::scheme_type::bfv)
    {
        std::cout << "|   plain_modulus: " << context_data.parms().plain_modulus().value() << '\n';
    }

    /*
    Print the security level.
    */
    int sec_lvl = static_cast<int>(context_data.qualifiers().sec_level);
    std::cout << "|   security_lvl: " << sec_lvl << '\n';

    /*
    For the benchmark mode, print the benchmark time.
    */
    if (mode == mode_type::bench)
    {
        std::cout << "|   bench_time: " << bench_time << '\n';
    }

    std::cout << "\\\n\n";
}

void run_internal(
    const mode_type mode, const SEALContext &context, const double scale, double data_bound, const unsigned bench_time, const unsigned test_loops)
{
    std::chrono::high_resolution_clock::time_point time_start, time_end;

    print_parameters(mode, context, scale, bench_time);

    std::cout << "Generating secret/public keys: ";
    KeyGenerator keygen(context);
    std::cout << "Done\n";

    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    RelinKeys relin_keys;
    GaloisKeys gal_keys;
    std::chrono::microseconds time_diff;
    if (context.using_keyswitching())
    {
        std::cout << "Generating relinearization keys: ";
        time_start = std::chrono::high_resolution_clock::now();
        keygen.create_relin_keys(relin_keys);
        time_end = std::chrono::high_resolution_clock::now();
        time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
        std::cout << "Done [" << time_diff.count() << " microseconds]\n";

        if (!context.first_context_data()->qualifiers().using_batching)
        {
            std::cout << "Given encryption parameters do not support batching.\n";
            return;
        }

        std::cout << "Generating Galois keys: ";
        time_start = std::chrono::high_resolution_clock::now();
        keygen.create_galois_keys(gal_keys);
        time_end = std::chrono::high_resolution_clock::now();
        time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
        std::cout << "Done [" << time_diff.count() << " microseconds]\n";
    }

    CKKSEncoder encoder(context);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);

    std::chrono::microseconds time_multiply_sum(0);
    std::chrono::microseconds time_relinearize_sum(0);
    std::chrono::microseconds time_rotate_one_step_sum(0);

    /*
    Populate a vector of floating-point values to batch.
    */
    std::vector<double> data;
    std::random_device rd;
    std::mt19937 gen(rd());
    if (data_bound == 0)
    {
        auto &context_data = *context.key_context_data();
        auto coeff_modulus = context_data.parms().coeff_modulus();
        std::vector<int> coeff_mod_bit_sizes;
        for (auto &&mod : coeff_modulus)
        {
            coeff_mod_bit_sizes.push_back(mod.bit_count());
        }
        auto data_bound_bit_size = *std::min_element(coeff_mod_bit_sizes.cbegin(), coeff_mod_bit_sizes.cend()) / 2;
        data_bound = static_cast<double>(1L << data_bound_bit_size);
    }
    std::uniform_real_distribution<double> distr(-data_bound, data_bound);
    data.resize(encoder.slot_count());

    Plaintext plain;
    Ciphertext encrypted(context);

    unsigned loop_count = 0;
    do {
        std::cout << '\n' << std::string("Running ") + (mode == mode_type::test ? "tests " : "benchmarks ");
        std::cout << "   ";
        long count = 0;
        int print_count = 0;
        bool print_dir = true;
        std::chrono::high_resolution_clock::time_point test_time_start = std::chrono::high_resolution_clock::now();
        do
        {
            // Fill input vector with random data
            for (size_t i = 0; i < data.size(); i++)
                // data[i] = static_cast<double>(distr(gen));
                data[i] = i;

            // [Encoding]
            encoder.encode(data, scale, plain);

            // [Encryption]
            encryptor.encrypt(plain, encrypted);

            // [Multiply]
            time_start = std::chrono::high_resolution_clock::now();
    #ifdef HEXL_FPGA
            intel::hexl::set_worksize_DyadicMultiply(1);
    #endif
            evaluator.multiply_inplace(encrypted, encrypted);
    #ifdef HEXL_FPGA
            intel::hexl::DyadicMultiplyCompleted();
    #endif
            time_end = std::chrono::high_resolution_clock::now();
            time_multiply_sum += std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);

            if (context.using_keyswitching())
            {
                // [Relinearize]
                time_start = std::chrono::high_resolution_clock::now();
        #ifdef HEXL_FPGA
                intel::hexl::set_worksize_KeySwitch(1);
        #endif
                evaluator.relinearize_inplace(encrypted, relin_keys);
        #ifdef HEXL_FPGA
                intel::hexl::KeySwitchCompleted();
        #endif
                time_end = std::chrono::high_resolution_clock::now();
                time_relinearize_sum += std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);

                // [Rescale]
                evaluator.rescale_to_next_inplace(encrypted);

                // [Rotate Vector]
                time_start = std::chrono::high_resolution_clock::now();
        #ifdef HEXL_FPGA
                intel::hexl::set_worksize_KeySwitch(1);
        #endif
                evaluator.rotate_vector_inplace(encrypted, 1, gal_keys);
        #ifdef HEXL_FPGA
                intel::hexl::KeySwitchCompleted();
        #endif
                // evaluator.rotate_vector_inplace(encrypted, -1, gal_keys);
                time_end = std::chrono::high_resolution_clock::now();
                time_rotate_one_step_sum += std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
            }

            // Print a dot to indicate progress.
            std::cout << "\b\b\b";
            for (auto i = 0; i < 3; ++i)
            {
                if (i < print_count)
                    std::cout << ".";
                else
                    std::cout << " ";
            }
            if (print_dir)
            {
                ++print_count;
                if (print_count >= 3)
                    print_dir = false;
            }
            else
            {
                --print_count;
                if (print_count <= 0)
                    print_dir = true;
            }
            std::cout.flush();

            ++count;
        } while (mode == mode_type::bench && std::chrono::duration_cast<std::chrono::seconds>(
                                                std::chrono::high_resolution_clock::now() - test_time_start)
                                                    .count() < bench_time);

        std::cout << "\b\b\b";
        std::cout << "...";

        std::cout << " Done\n\n";

        auto avg_multiply = time_multiply_sum.count() / count;
        auto avg_relinearize = time_relinearize_sum.count() / count;
        auto avg_rotate_one_step = time_rotate_one_step_sum.count() / (2 * count);

        if (context.using_keyswitching())
        {
            std::cout << "Average multiply: " << avg_multiply << " microseconds\n";
            std::cout << "Average relinearize: " << avg_relinearize << " microseconds\n";
            std::cout << "Average rotate vector one step: " << avg_rotate_one_step << " microseconds\n";
        }
        std::cout << '\n';

        if (mode == mode_type::bench)
            return;

        // [Decryption]
        Plaintext plain2;
        Decryptor decryptor(context, secret_key);
        decryptor.decrypt(encrypted, plain2);

        // [Decoding]
        std::vector<double> data2;
        encoder.decode(plain2, data2);

        // Transform original (expected) data
        std::transform(data.begin(), data.end(), data.begin(), [](double d) { return d * d; });
        std::rotate(data.begin(), data.begin() + 1, data.end());
        // std::rotate(data.rbegin(), data.rbegin() + 1, data.rend());

        if (data.size() != data2.size())
        {
            std::cout << "ERROR: Functionally incorrect: Input and ouput vectors have different sizes.\n\n";
            return;
        }

        for (size_t i = 0; i < data.size(); ++i)
        {
            if (std::abs(data[i] - data2[i]) >= 0.5)
            {
                std::cout << "expected[" << i << "]=" << data[i] << " output[" << i << "]=" << data2[i] << '\n';
                std::cout << "ERROR: Functionally incorrect: One or more values differ between expected and output.\n\n";
                return;
            }
        }

        std::cout << "SUCCESS: Test passed.\n\n";
        ++loop_count;
    } while (mode == mode_type::test && loop_count < test_loops);
}

void run(
    const mode_type mode, const size_t poly_modulus_degree, const std::vector<int> &coeff_mod_bit_sizes,
    const unsigned scale_bit_size, const sec_level_type sec_lvl, const double data_bound, const unsigned bench_time, const unsigned test_loops)
{
    EncryptionParameters params(scheme_type::ckks);
    params.set_poly_modulus_degree(poly_modulus_degree);
    if (mode == mode_type::bench && coeff_mod_bit_sizes.size() == 1 && coeff_mod_bit_sizes[0] == 0)
    {
        // For benchmarking, BFVDefault primes are good enough.
        params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    }
    else
    {
        params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, coeff_mod_bit_sizes));
    }

    double scale;
    if (mode == mode_type::bench && scale_bit_size == 0)
    {
        // For benchmarking setting the scale as the square root of the last coeff_modulus prime is good enough.
        scale = std::sqrt(static_cast<double>(params.coeff_modulus().back().value()));
    }
    else
    {
        scale = static_cast<double>(1UL << scale_bit_size);
    }

    SEALContext context(params, true, sec_lvl);

    if (mode == mode_type::test)
    {
        run_internal(mode_type::test, context, scale, data_bound, 0, test_loops);
    }
    else if (mode == mode_type::bench)
    {
        run_internal(mode_type::bench, context, scale, data_bound, bench_time, 0);
    }
}

DEFINE_string(mode, "test", "Run mode. Must be either test or bench.");
// DEFINE_string(scheme, "ckks", "HE scheme. Must be either ckks or bfv.");
DEFINE_uint32(
    poly_modulus_degree, 8192, "Degree of the polynomial modulus. Must be a power of 2 between 1024 and 32768.");
DEFINE_string(
    coeff_mod_bit_sizes, "0",
    "Cefficient modulus. Comma-separated list of bit-lengths of the primes to be generated. Values must be between 1 "
    "and 60. The default (0) is valid only for benchmark mode and uses the BFVDefault primes at a security level of "
    "128.");
DEFINE_uint32(
    scale_bit_size, 0,
    "Bit-length for the scaling parameter, which defines encoding precision. Scale will be set as 2^scale_bit_size." /* Only applies to the CKKS scheme.*/
    " Must be between 1 and 60. The default (0) is valid only for benchmark mode and sets it to the square root of the "
    "last prime of the coefficient modulus.");
// DEFINE_uint64(plain_modulus, 786433, "Plaintext modulus. Only applies to the BFV scheme. Must be at most 60 bits
// long.");
DEFINE_uint32(security_lvl, 0, "Security level. One of {0, 128, 192, 256}.");
DEFINE_double(
    data_bound, 0,
    "Limit for the random data generated for the test input vector. Simetric in the positive and negative axes. The "
    "default (0) sets it to a power of two, where the power is the minimum of coeff_mod_bit_sizes, divided by two.");
DEFINE_uint32(
    bench_time, 30, "Minimum run time, in seconds, when running in benchmark mode. Must be between 1 and 3600.");
DEFINE_uint32(test_loops, 1, "Amount of times to run the test, when running in test mode. Must be between 1 and 10000.");

int main(int argc, char *argv[])
{
    gflags::ParseCommandLineFlags(&argc, &argv, true);

    mode_type mode;
    if (FLAGS_mode == "test")
    {
        mode = mode_type::test;
    }
    else if (FLAGS_mode == "bench")
    {
        mode = mode_type::bench;
    }
    else
    {
        std::cout << "ERROR: mode must be either test or bench.\n";
        return EXIT_FAILURE;
    }
    if (FLAGS_bench_time < 1 || FLAGS_bench_time > 3600)
    {
        std::cout << "ERROR: bench_time must be between 1 and 3600.\n";
        return EXIT_FAILURE;
    }
    if (FLAGS_poly_modulus_degree < 1024 || FLAGS_poly_modulus_degree > 32768 ||
        FLAGS_poly_modulus_degree & (FLAGS_poly_modulus_degree - 1) == 0)
    {
        std::cout << "ERROR: poly_modulus_degree must be a power of 2 between 1024 and 32768.\n";
        return EXIT_FAILURE;
    }
    std::vector<int> coeff_mod_bit_sizes;
    std::stringstream ss(FLAGS_coeff_mod_bit_sizes);
    for (int i; ss >> i;)
    {
        coeff_mod_bit_sizes.push_back(i);
        if (ss.peek() == ',')
            ss.ignore();
    }
    if (coeff_mod_bit_sizes.size() == 0)
    {
        std::cout << "ERROR: coeff_mod_bit_sizes must contain at least one element.\n";
        return EXIT_FAILURE;
    }
    for (int val : coeff_mod_bit_sizes)
    {
        if (val < 0 || val > 60 || (val == 0 && (mode != mode_type::bench || coeff_mod_bit_sizes.size() != 1)))
        {
            std::cout << "ERROR: coeff_mod_bit_sizes values must be between 1 and 60.\n";
            return EXIT_FAILURE;
        }
    }
    if ((FLAGS_scale_bit_size == 0 && mode != mode_type::bench) || FLAGS_scale_bit_size > 60)
    {
        std::cout << "ERROR: scale_bit_size must be between 1 and 60.\n";
        return EXIT_FAILURE;
    }
    sec_level_type sec_lvl;
    switch (FLAGS_security_lvl)
    {
    case 0:
        sec_lvl = sec_level_type::none;
        break;
    case 128:
        sec_lvl = sec_level_type::tc128;
        break;
    case 192:
        sec_lvl = sec_level_type::tc192;
        break;
    case 256:
        sec_lvl = sec_level_type::tc256;
        break;
    default:
        std::cout << "ERROR: security_lvl must be one of {0, 128, 192, 256}.\n";
        return EXIT_FAILURE;
    }
    if (FLAGS_data_bound < 0)
    {
        std::cout << "ERROR: data_bound can't be negative.\n";
        return EXIT_FAILURE;
    }
    if (FLAGS_bench_time < 1 || FLAGS_bench_time > 3600)
    {
        std::cout << "ERROR: bench_time must be between 1 and 3600.\n";
        return EXIT_FAILURE;
    }
    if (FLAGS_test_loops < 1 || FLAGS_test_loops > 10000)
    {
        std::cout << "ERROR: test_loops must be between 1 and 10000.\n";
        return EXIT_FAILURE;
    }

#ifdef HEXL_FPGA
    intel::hexl::acquire_FPGA_resources();
#endif
    run(mode, FLAGS_poly_modulus_degree, coeff_mod_bit_sizes, FLAGS_scale_bit_size, sec_lvl, FLAGS_data_bound,
        FLAGS_bench_time, FLAGS_test_loops);
#ifdef HEXL_FPGA
    intel::hexl::release_FPGA_resources();
#endif

    return 0;
}
