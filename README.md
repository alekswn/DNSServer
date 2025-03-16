# DNS Server Implementation in C++

## Overview
This project implements a DNS server based on RFC 1035. The server will handle DNS queries, respond to requests, and manage DNS records.

## Directory Structure
- `src/` - Contains the source code for the DNS server.
- `include/` - Contains header files.
- `tests/` - Contains unit tests for the server.
- `Makefile` - Build script to compile the project.
- `README.md` - Project documentation.
- `CMakeLists.txt` - CMake build configuration for the project and tests.

## Requirements
- C++11 or later
- g++ compiler
- CMake 3.10 or later (for building tests)
- Internet connection (for fetching Google Test during test build)

## Building the Project
### Using Makefile
To build the project using the Makefile, run:
```bash
make
```

### Using CMake
To build the project and tests using CMake, run:
```bash
mkdir build
cd build
cmake ..
make
```

## Running the Server
To run the server, execute:
```bash
./dns_server
```

## Running the Tests
The project includes a comprehensive test suite based on RFC1035 specifications. The test suite is built using Google Test framework and tests various aspects of DNS server functionality.

### Building and Running Tests with CMake
```bash
mkdir -p build
cd build
cmake ..
make
```

### Running Specific Tests
After building the tests, you can run them individually:
```bash
# Run all DNS server tests
./dns_server_test

# Run DNS record handling tests
./dns_record_test
```

### Running All Tests
You can also run all tests at once using CTest:
```bash
cd build
ctest
```

## Test Suite Overview
The test suite consists of:

1. **RFC1035 Compliance Tests**
   - DNS message format and header flags testing
   - Resource record type handling (A, MX, NS, CNAME, SOA, PTR, TXT)
   - Domain name handling including case insensitivity
   - DNS message compression tests
   - Query and response validation

2. **DNS Record Tests**
   - Basic record addition and retrieval testing
   - Multiple record handling
   - Non-existent domain handling
   - Case sensitivity handling

## Notes on RFC1035 Compliance
The test suite is designed to verify compliance with key aspects of RFC1035, which defines the Domain Name System specifications, including:

- Message format and encoding (Section 4)
- Resource Record definitions (Section 3)
- Name handling and resolution (Section 2.3)
- Query types and response codes
