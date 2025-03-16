#include "catch.hpp"
#include "../src/dns_server.h"
#include <vector>
#include <string>

// Simple direct unit tests for the current implementation
TEST_CASE("DNS Record Tests", "[dns_records]") {
    DNSServer server;
    
    // Add some basic test records
    server.addRecord("example.com", RecordType::A, "192.0.2.1");
    server.addRecord("example.com", "MX", "mail.example.com");
    server.addRecord("example.com", "NS", "ns.example.com");
    server.addRecord("example.com", "TXT", "This is a test record");
    server.addRecord("subdomain.example.com", RecordType::A, "192.0.2.2");
    
    SECTION("Add And Query A Record") {
        // Add a new A record
        server.addRecord("test.example.com", RecordType::A, "192.0.2.3");
        
        // Query for the record
        std::vector<DNSRecord> results = server.query("test.example.com");
        
        // Verify the record was added and retrieved correctly
        REQUIRE(results.size() == 1);
        CHECK(results[0].name == "test.example.com");
        CHECK(results[0].type == "A");
        CHECK(results[0].value == "192.0.2.3");
    }
    
    SECTION("Query Multiple Records") {
        std::vector<DNSRecord> results = server.query("example.com");
        
        REQUIRE(results.size() == 4);
        
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
        
        CHECK(aCount == 1);
        CHECK(mxCount == 1);
        CHECK(nsCount == 1);
        CHECK(txtCount == 1);
    }
    
    SECTION("Query Nonexistent Domain") {
        std::vector<DNSRecord> results = server.query("nonexistent.com");
        
        CHECK(results.empty());
    }
    
    SECTION("Query Case Insensitive") {
        std::vector<DNSRecord> results = server.query("EXAMPLE.COM");
        
        // DNS domain names should be case insensitive per RFC1035
        REQUIRE(results.size() == 4);
    }
    
    SECTION("Multiple Records Same Name And Type") {
        server.addRecord("multi.example.com", RecordType::A, "192.0.2.10");
        server.addRecord("multi.example.com", RecordType::A, "192.0.2.11");
        
        std::vector<DNSRecord> results = server.query("multi.example.com");
        
        REQUIRE(results.size() == 2);
        
        bool found10 = false;
        bool found11 = false;
        
        for (const auto& record : results) {
            if (record.value == "192.0.2.10") found10 = true;
            if (record.value == "192.0.2.11") found11 = true;
        }
        
        CHECK(found10);
        CHECK(found11);
    }
    
    SECTION("Test queryByType Method") {
        // Add different record types
        server.addRecord("type-test.example.com", RecordType::A, "192.0.2.20");
        server.addRecord("type-test.example.com", "MX", "mail.example.com");
        server.addRecord("type-test.example.com", RecordType::NS, "ns.example.com");
        
        // Query specifically for A records
        auto aRecords = server.queryByType("type-test.example.com", RecordType::A);
        REQUIRE(aRecords.size() == 1);
        CHECK(aRecords[0].type == "A");
        CHECK(aRecords[0].value == "192.0.2.20");
        
        // Query specifically for MX records
        auto mxRecords = server.queryByType("type-test.example.com", "MX");
        REQUIRE(mxRecords.size() == 1);
        CHECK(mxRecords[0].type == "MX");
        CHECK(mxRecords[0].value == "mail.example.com");
    }
}
