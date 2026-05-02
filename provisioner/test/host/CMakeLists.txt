cmake_minimum_required(VERSION 3.16)
project(provisioner_proto_host_tests C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
add_compile_options(-Wall -Wextra -Wpedantic -Werror)

# Build the protocol unit under test plus a tiny self-contained mbedtls
# base64 stub so the host test does not depend on a system mbedtls install.
add_executable(test_proto
    test_proto.c
    mbedtls_base64_stub.c
    ../../src/provisioner_proto.c
)

target_include_directories(test_proto PRIVATE
    .
    ../../src
)

enable_testing()
add_test(NAME proto COMMAND test_proto)
