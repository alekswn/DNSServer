cmake_minimum_required(VERSION 3.10)
project(DNSServer)

# Set C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include directories
include_directories(src)

# Create a library for the DNS server implementation
add_library(dns_server_lib src/dns_server.cpp)

# Main DNS server executable
add_executable(dns_server src/main.cpp)
target_link_libraries(dns_server dns_server_lib)

# Enable testing
enable_testing()

# Find or download GoogleTest
include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG release-1.12.1
)
FetchContent_MakeAvailable(googletest)

# Add the tests executables
add_executable(dns_server_test tests/dns_server_test.cpp)
add_executable(dns_record_test tests/dns_record_test.cpp)

# Link with GoogleTest and the DNS server library
target_link_libraries(dns_server_test gtest gtest_main dns_server_lib pthread)
target_link_libraries(dns_record_test gtest gtest_main dns_server_lib pthread)

# Add tests to CTest
add_test(NAME DNSServerTest COMMAND dns_server_test)
add_test(NAME DNSRecordTest COMMAND dns_record_test)
