# Makefile for DNS Server and tests with Catch2

# Compiler and flags
CXX = clang++
CXXFLAGS = -std=c++20 -Wall -Wextra -g -pedantic -Werror
LDFLAGS = -pthread

# Directories
SRC_DIR = src
TEST_DIR = tests
BUILD_DIR = build
CATCH2_DIR = $(BUILD_DIR)/catch2

# Files
SERVER_SRC = $(SRC_DIR)/dns_server.cpp
MAIN_SRC = $(SRC_DIR)/main.cpp
SERVER_OBJ = $(BUILD_DIR)/dns_server.o
MAIN_OBJ = $(BUILD_DIR)/main.o

SERVER_TEST_SRC = $(TEST_DIR)/dns_server_test.cpp
RECORD_TEST_SRC = $(TEST_DIR)/dns_record_test.cpp
TEST_MAIN_SRC = $(TEST_DIR)/test_main.cpp
SERVER_TEST_OBJ = $(BUILD_DIR)/dns_server_test.o
RECORD_TEST_OBJ = $(BUILD_DIR)/dns_record_test.o
TEST_MAIN_OBJ = $(BUILD_DIR)/test_main.o

# Targets
SERVER_TARGET = $(BUILD_DIR)/dns_server
LIB_TARGET = $(BUILD_DIR)/libdns_server.a
ALL_TESTS_TARGET = $(BUILD_DIR)/run_tests
SERVER_TEST_TARGET = $(BUILD_DIR)/dns_server_test
RECORD_TEST_TARGET = $(BUILD_DIR)/dns_record_test

# Catch2 single header URL
CATCH2_URL = https://github.com/catchorg/Catch2/releases/download/v2.13.10/catch.hpp
CATCH2_HEADER = $(CATCH2_DIR)/catch.hpp

# Default target
all: prepare $(SERVER_TARGET)

# Build everything including tests
everything: all tests

# Prepare build directories
prepare:
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(CATCH2_DIR)

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)

# Objects
$(SERVER_OBJ): $(SERVER_SRC)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(MAIN_OBJ): $(MAIN_SRC)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# DNS Server Library
$(LIB_TARGET): $(SERVER_OBJ)
	ar rcs $@ $^

# DNS Server Executable
$(SERVER_TARGET): $(MAIN_OBJ) $(LIB_TARGET)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

# Run the server
run: $(SERVER_TARGET)
	$(SERVER_TARGET)

# Catch2 Header
$(CATCH2_HEADER):
	@mkdir -p $(CATCH2_DIR)
	@echo "Downloading Catch2 header..."
	@curl -sSL $(CATCH2_URL) -o $(CATCH2_HEADER)

# Test main object
$(TEST_MAIN_OBJ): $(TEST_MAIN_SRC) $(CATCH2_HEADER)
	$(CXX) $(CXXFLAGS) -I$(CATCH2_DIR) -I$(SRC_DIR) -c $< -o $@

# Test objects
$(SERVER_TEST_OBJ): $(SERVER_TEST_SRC) $(CATCH2_HEADER)
	$(CXX) $(CXXFLAGS) -I$(CATCH2_DIR) -I$(SRC_DIR) -c $< -o $@

$(RECORD_TEST_OBJ): $(RECORD_TEST_SRC) $(CATCH2_HEADER)
	$(CXX) $(CXXFLAGS) -I$(CATCH2_DIR) -I$(SRC_DIR) -c $< -o $@

# Test executables
$(ALL_TESTS_TARGET): $(TEST_MAIN_OBJ) $(SERVER_TEST_OBJ) $(RECORD_TEST_OBJ) $(LIB_TARGET)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

# Build all tests
tests: $(ALL_TESTS_TARGET)

# Run tests
test: tests
	@echo "Running DNS Server Tests..."
	@$(ALL_TESTS_TARGET)

# Install target (optional)
install: $(SERVER_TARGET)
	@echo "Installing DNS Server to /usr/local/bin (requires sudo)"
	@sudo cp $(SERVER_TARGET) /usr/local/bin/

.PHONY: all everything prepare clean run tests test install
