# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


add_executable(crypto-extra_enc enc.cpp)

target_compile_options(crypto-extra_enc PRIVATE
    -std=c++11
)

target_link_libraries(crypto-extra_enc oelibcxx oeenclave)
