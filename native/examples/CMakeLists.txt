# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.13)

project(SEALExamples VERSION 3.7.2 LANGUAGES CXX)

# If not called from root CMakeLists.txt
if(NOT DEFINED SEAL_BUILD_EXAMPLES)
    set(SEAL_BUILD_EXAMPLES ON)

    # Import Microsoft SEAL
    find_package(SEAL 3.7.2 EXACT REQUIRED)

    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
endif()

if(SEAL_BUILD_EXAMPLES)
    include(cmake/gflags.cmake)

    add_executable(sealexamples)
    add_executable(fpga-ckks-example)
    target_sources(sealexamples
        PRIVATE
            ${CMAKE_CURRENT_LIST_DIR}/examples.cpp
            ${CMAKE_CURRENT_LIST_DIR}/1_bfv_basics.cpp
            ${CMAKE_CURRENT_LIST_DIR}/2_encoders.cpp
            ${CMAKE_CURRENT_LIST_DIR}/3_levels.cpp
            ${CMAKE_CURRENT_LIST_DIR}/4_ckks_basics.cpp
            ${CMAKE_CURRENT_LIST_DIR}/5_rotation.cpp
            ${CMAKE_CURRENT_LIST_DIR}/6_serialization.cpp
            ${CMAKE_CURRENT_LIST_DIR}/7_performance.cpp
    )
    target_sources(fpga-ckks-example
        PRIVATE
            ${CMAKE_CURRENT_LIST_DIR}/fpga-ckks-example.cpp
    )

    if(TARGET SEAL::seal)
        target_link_libraries(sealexamples PRIVATE SEAL::seal)
        target_link_libraries(fpga-ckks-example PRIVATE SEAL::seal)
    elseif(TARGET SEAL::seal_shared)
        target_link_libraries(sealexamples PRIVATE SEAL::seal_shared)
        target_link_libraries(fpga-ckks-example PRIVATE SEAL::seal_shared)
    else()
        message(FATAL_ERROR "Cannot find target SEAL::seal or SEAL::seal_shared")
    endif()

    if(SEAL_USE_INTEL_HEXL_FPGA)
        add_definitions(-DHEXL_FPGA)
        find_package(hexl-fpga)
        if(TARGET hexl-fpga::hexl-fpga)
            target_link_libraries(sealexamples PRIVATE hexl-fpga::hexl-fpga)
            target_link_libraries(fpga-ckks-example PRIVATE hexl-fpga::hexl-fpga)
        elseif(TARGET hexl-fpga)
            target_link_libraries(sealexamples PRIVATE hexl-fpga)
            target_link_libraries(fpga-ckks-example PRIVATE hexl-fpga)
        else()
            message(FATAL_ERROR "Cannot find target hexl-fpga")
        endif()
    endif()

    target_link_libraries(fpga-ckks-example PRIVATE libgflags)
endif()
