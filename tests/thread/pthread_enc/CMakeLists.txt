# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


add_executable(pthread_enc
    enc.cpp
    cond_tests.cpp
    rwlock_tests.cpp)

target_link_libraries(pthread_enc oelibcxx oeenclave)
