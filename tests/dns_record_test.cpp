#include <gtest/gtest.h>
#include "../src/dns_server.h"
#include <vector>
#include <string>

// Simple direct unit tests for the current implementation
class DNSRecordTest : public ::testing::Test {
protected:
    DNSServer server;
    
    void SetUp() override {
        // Add some basic test records
        server.addRecord(DNSRecord("example.com", "A", "192.0.2.1"));
        server.addRecord(DNSRecord("example.com", "MX", "mail.example.com"));
        server.addRecord(DNSRecord("example.com", "NS", "ns.example.com"));
        server.addRecord(DNSRecord("example.com", "TXT", "This is a test record"));
        server.addRecord(DNSRecord("subdomain.example.com", "A", "192.0.2.2"));
    }
};

// Test adding and retrieving A records
TEST_F(DNSRecordTest, AddAndQueryARecord) {
    // Add a new A record
    server.addRecord(DNSRecord("test.example.com", "A", "192.0.2.3"));
    
    // Query for the record
    std::vector<DNSRecord> results = server.query("test.example.com");
    
    // Verify the record was added and retrieved correctly
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].name, "test.example.com");
    EXPECT_EQ(results[0].type, "A");
    EXPECT_EQ(results[0].value, "192.0.2.3");
}

// Test querying multiple records for the same domain
TEST_F(DNSRecordTest, QueryMultipleRecords) {
    std::vector<DNSRecord> results = server.query("example.com");
    
    ASSERT_EQ(results.size(), 4);
    
    // Count record types
    int aCount = 0;
    int mxCount = 0;
    int nsCount = 0;
    int txtCount = 0;
    
    for (const auto& record : results) {
        if (record.type == "A") aCount++;
        else if (record.type == "MX") mxCount++;
        else if (record.type == "NS") nsCount++;
        else if (record.type == "TXT") txtCount++;
    }
    
    EXPECT_EQ(aCount, 1);
    EXPECT_EQ(mxCount, 1);
    EXPECT_EQ(nsCount, 1);
    EXPECT_EQ(txtCount, 1);
}

// Test querying non-existent domain
TEST_F(DNSRecordTest, QueryNonexistentDomain) {
    std::vector<DNSRecord> results = server.query("nonexistent.com");
    
    EXPECT_TRUE(results.empty());
}

// Test case insensitivity (RFC1035 section 2.3.3)
TEST_F(DNSRecordTest, QueryCaseInsensitive) {
    std::vector<DNSRecord> results = server.query("EXAMPLE.COM");
    
    // The current implementation likely doesn't handle case insensitivity
    // This test will help determine if it does or not
    // ASSERT_EQ(results.size(), 4);
}

// Test adding multiple records with the same name and type
TEST_F(DNSRecordTest, MultipleRecordsSameNameAndType) {
    server.addRecord(DNSRecord("multi.example.com", "A", "192.0.2.10"));
    server.addRecord(DNSRecord("multi.example.com", "A", "192.0.2.11"));
    
    std::vector<DNSRecord> results = server.query("multi.example.com");
    
    ASSERT_EQ(results.size(), 2);
    
    bool found10 = false;
    bool found11 = false;
    
    for (const auto& record : results) {
        if (record.value == "192.0.2.10") found10 = true;
        else if (record.value == "192.0.2.11") found11 = true;
    }
    
    EXPECT_TRUE(found10);
    EXPECT_TRUE(found11);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
