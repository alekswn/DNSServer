# DNS Server Implementation

## Overview
This project implements a DNS server based on RFC 1035. The server handles DNS queries, responds to requests, and manages DNS records. It's built using modern C++20 features for improved performance and maintainability.

## Project Structure
- `cpp/` - C++ implementation of the DNS server
  - `src/` - Source code for the DNS server
  - `tests/` - Unit tests using Catch2
  - `Makefile` - Makefile for building with clang++
- `acceptance_tests/` - Python-based acceptance tests for protocol compliance
- `justfile` - Task runner for common operations
- `.github/workflows/` - GitHub Actions CI configuration

## Modern C++ Features

This implementation leverages C++20 features:
- `std::string_view` for zero-copy string operations
- `std::span` for safer buffer handling
- Strongly typed enums for record types
- Const-correctness throughout the codebase
- Compiler warnings treated as errors for high code quality

## Quick Start with Just

The project uses [just](https://github.com/casey/just) as a task runner to simplify common operations. To get started:

1. Install just:
   ```bash
   # On Ubuntu/Debian
   apt install just
   
   # On macOS
   brew install just
   ```

2. Run available commands:
   ```bash
   # List all available commands
   just
   
   # Build the C++ implementation
   just build
   
   # Run C++ unit tests
   just test-cpp
   
   # Run acceptance tests
   just test-acceptance
   
   # Run all tests
   just test-all
   
   # Run the DNS server
   just run
   ```

## Continuous Integration

This project uses GitHub Actions for continuous integration. The CI pipeline:
- Builds the DNS server with clang++
- Runs all unit tests
- Runs acceptance tests to verify protocol compliance

The configuration is in `.github/workflows/ci.yml`.

## C++ Implementation

### Requirements
- C++20 or later
- clang++ compiler
- CMake 3.10 or later (for building tests)
- Internet connection (for fetching Catch2 during test build)

### Building the Project
#### Using Makefile
```bash
cd cpp
make
```

#### Using CMake
```bash
cd cpp
mkdir -p build
cd build
cmake ..
make
```

#### Using Just
```bash
just build
```

### Running the Server
```bash
cd cpp/build
./dns_server
```

Or with just:
```bash
just run
```

### Running the Unit Tests
```bash
cd cpp/build
./dns_server_test
./dns_record_test
```

Or with just:
```bash
just test-cpp
```

## Acceptance Tests

### Requirements
- Python 3.7+
- Packages listed in `acceptance_tests/requirements.txt`

### Setup
```bash
cd acceptance_tests
pip install -r requirements.txt
```

Or with just:
```bash
just setup-acceptance-tests
```

### Running the Acceptance Tests
```bash
cd acceptance_tests
pytest -v
```

Or with just:
```bash
just test-acceptance
```

## DNS Protocol Compliance
The implementation aims to be fully compliant with RFC 1035 specifications, including:
- Message format and header flags
- Resource record types (A, MX, NS, CNAME, SOA, PTR, TXT)
- Domain name handling with case insensitivity
- DNS message compression
- Error handling
