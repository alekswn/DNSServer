# Makefile for DNS Server and tests

# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra -g
LDFLAGS = -pthread

# Directories
SRC_DIR = src
TEST_DIR = tests
BUILD_DIR = build
GTEST_DIR = $(BUILD_DIR)/gtest

# Files
SERVER_SRC = $(SRC_DIR)/dns_server.cpp
MAIN_SRC = $(SRC_DIR)/main.cpp
SERVER_OBJ = $(BUILD_DIR)/dns_server.o
MAIN_OBJ = $(BUILD_DIR)/main.o

SERVER_TEST_SRC = $(TEST_DIR)/dns_server_test.cpp
RECORD_TEST_SRC = $(TEST_DIR)/dns_record_test.cpp
SERVER_TEST_OBJ = $(BUILD_DIR)/dns_server_test.o
RECORD_TEST_OBJ = $(BUILD_DIR)/dns_record_test.o

# Targets
SERVER_TARGET = $(BUILD_DIR)/dns_server
LIB_TARGET = $(BUILD_DIR)/libdns_server.a
SERVER_TEST_TARGET = $(BUILD_DIR)/dns_server_test
RECORD_TEST_TARGET = $(BUILD_DIR)/dns_record_test

# GoogleTest
GTEST_REPO = https://github.com/google/googletest.git
GTEST_TAG = release-1.12.1
GTEST_LIB = $(GTEST_DIR)/lib/libgtest.a
GTEST_MAIN_LIB = $(GTEST_DIR)/lib/libgtest_main.a
GTEST_INCLUDE = $(GTEST_DIR)/include

# Default target
all: prepare $(SERVER_TARGET)

# Build everything including tests
everything: all tests

# Prepare build directories
prepare:
	@mkdir -p $(BUILD_DIR)

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

# GoogleTest setup
$(GTEST_DIR):
	@mkdir -p $(GTEST_DIR)
	@echo "Downloading GoogleTest..."
	@git clone -b $(GTEST_TAG) --depth 1 $(GTEST_REPO) $(GTEST_DIR)/src
	@cd $(GTEST_DIR)/src && mkdir -p build && cd build && \
	cmake .. && make
	@mkdir -p $(GTEST_DIR)/lib $(GTEST_DIR)/include
	@cp $(GTEST_DIR)/src/build/lib/libgtest*.a $(GTEST_DIR)/lib/
	@cp -r $(GTEST_DIR)/src/googletest/include/gtest $(GTEST_DIR)/include/

# Test objects
$(SERVER_TEST_OBJ): $(SERVER_TEST_SRC) $(GTEST_DIR)
	$(CXX) $(CXXFLAGS) -I$(GTEST_INCLUDE) -I$(SRC_DIR) -c $< -o $@

$(RECORD_TEST_OBJ): $(RECORD_TEST_SRC) $(GTEST_DIR)
	$(CXX) $(CXXFLAGS) -I$(GTEST_INCLUDE) -I$(SRC_DIR) -c $< -o $@

# Test executables
$(SERVER_TEST_TARGET): $(SERVER_TEST_OBJ) $(LIB_TARGET) $(GTEST_DIR)
	$(CXX) $(CXXFLAGS) $< $(LIB_TARGET) $(GTEST_LIB) $(GTEST_MAIN_LIB) -o $@ $(LDFLAGS)

$(RECORD_TEST_TARGET): $(RECORD_TEST_OBJ) $(LIB_TARGET) $(GTEST_DIR)
	$(CXX) $(CXXFLAGS) $< $(LIB_TARGET) $(GTEST_LIB) $(GTEST_MAIN_LIB) -o $@ $(LDFLAGS)

# Build all tests
tests: $(SERVER_TEST_TARGET) $(RECORD_TEST_TARGET)

# Run tests
test: tests
	@echo "Running DNS Server Tests..."
	@$(SERVER_TEST_TARGET)
	@echo "Running DNS Record Tests..."
	@$(RECORD_TEST_TARGET)

# Install target (optional)
install: $(SERVER_TARGET)
	@echo "Installing DNS Server to /usr/local/bin (requires sudo)"
	@sudo cp $(SERVER_TARGET) /usr/local/bin/

.PHONY: all everything prepare clean run tests test install
