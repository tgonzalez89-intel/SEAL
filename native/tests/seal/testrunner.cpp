// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"
#ifdef HEXL_FPGA
#include "hexl-fpga.h"
#endif

/**
Main entry point for Google Test unit tests.
*/
int main(int argc, char **argv)
{
    testing::InitGoogleTest(&argc, argv);
#ifdef HEXL_FPGA
    intel::hexl::acquire_FPGA_resources();
#endif
    auto result = RUN_ALL_TESTS();
#ifdef HEXL_FPGA
    intel::hexl::release_FPGA_resources();
#endif
    return result;
}
