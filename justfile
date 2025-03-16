# DNS Server justfile
# This file contains recipes for common tasks
# To use, install "just" from https://github.com/casey/just

# List available recipes
default:
    @just --list

# Build the C++ implementation
build:
    mkdir -p cpp/build
    cd cpp/build && cmake .. && make

# Clean build artifacts
clean:
    rm -rf cpp/build

# Run the C++ unit tests
test-cpp: build
    cd cpp/build && ./dns_server_test
    cd cpp/build && ./dns_record_test

# Run all unit tests with ctest
test-cpp-all: build
    cd cpp/build && ctest

# Install Python dependencies for acceptance tests
setup-acceptance-tests:
    pip install -r acceptance_tests/requirements.txt

# Run the Python acceptance tests
test-acceptance: build setup-acceptance-tests
    cd acceptance_tests && python -m pytest -v

# Generate HTML report for acceptance tests
test-acceptance-report: build setup-acceptance-tests
    cd acceptance_tests && python -m pytest --html=report.html

# Run the DNS server
run: build
    cd cpp/build && ./dns_server

# Run all tests (unit tests and acceptance tests)
test-all: test-cpp test-acceptance

# Clean everything and rebuild
rebuild: clean build
