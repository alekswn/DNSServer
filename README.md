# DNS Server Implementation

## Overview
This project implements a DNS server based on RFC 1035. The server handles DNS queries, responds to requests, and manages DNS records.

## Project Structure
- `cpp/` - C++ implementation of the DNS server
  - `src/` - Source code for the DNS server
  - `tests/` - Unit tests using Google Test
  - `CMakeLists.txt` - CMake build configuration
  - `Makefile` - Simple Makefile for building without CMake
- `acceptance_tests/` - Python-based acceptance tests for protocol compliance

## C++ Implementation

### Requirements
- C++11 or later
- g++ compiler
- CMake 3.10 or later (for building tests)
- Internet connection (for fetching Google Test during test build)

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

### Running the Server
```bash
cd cpp/build
./dns_server
```

### Running the Unit Tests
```bash
cd cpp/build
./dns_server_test
./dns_record_test
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

### Running the Acceptance Tests
```bash
cd acceptance_tests
pytest -v
```

## DNS Protocol Compliance
The implementation aims to be fully compliant with RFC 1035 specifications, including:
- Message format and header flags
- Resource record types (A, MX, NS, CNAME, SOA, PTR, TXT)
- Domain name handling with case insensitivity
- DNS message compression
- Error handling
