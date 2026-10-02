cmake_minimum_required(VERSION 3.13)
project(arm64_jni_inline_hook C)

set(CMAKE_C_STANDARD 11)

# ---------------------------------------------------------------------------
# Shared library: the hook framework core. Link into (or ship alongside) your
# injection .so. Headers are in include/.
# ---------------------------------------------------------------------------
add_library(jnihook SHARED src/jnihook.c)
target_include_directories(jnihook PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

# ---------------------------------------------------------------------------
# Example injection .so: link jnihook and compile as a shared object to be
# loaded by the target process via arbitrary-.so-injection.
# ---------------------------------------------------------------------------
add_library(resource_api_dump SHARED examples/resource_api_dump.c)
target_include_directories(resource_api_dump
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(resource_api_dump PRIVATE jnihook log)

# ---------------------------------------------------------------------------
# Host-side unit tests (pure logic only — no device required).
# ---------------------------------------------------------------------------
enable_testing()
add_executable(test_pic tests/test_pic.c src/jnihook.c)
target_include_directories(test_pic PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
add_test(NAME test_pic COMMAND test_pic)
