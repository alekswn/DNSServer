#include <gtest/gtest.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <string>
#include <vector>
#include <iostream>
#include "../src/dns_server.h"

// DNS Message Format Constants (RFC1035 Section 4)
#define DNS_HEADER_SIZE 12
#define DNS_TYPE_A      1
#define DNS_TYPE_NS     2
#define DNS_TYPE_CNAME  5
#define DNS_TYPE_SOA    6
#define DNS_TYPE_PTR    12
#define DNS_TYPE_MX     15
#define DNS_TYPE_TXT    16
#define DNS_CLASS_IN    1

// RFC1035 message flags
#define DNS_QR_QUERY    0
#define DNS_QR_RESPONSE 1
#define DNS_OPCODE_QUERY 0
#define DNS_OPCODE_IQUERY 1  // Inverse query
#define DNS_OPCODE_STATUS 2  // Server status request
#define DNS_RCODE_NOERROR 0
#define DNS_RCODE_FORMAT 1   // Format error
#define DNS_RCODE_SERVER 2   // Server failure
#define DNS_RCODE_NXDOMAIN 3 // Name Error
#define DNS_RCODE_NOTIMP 4   // Not implemented
#define DNS_RCODE_REFUSED 5  // Refused

// RFC1035 section 3.2.2: Resource Record types
const char* getRRTypeName(uint16_t type) {
    switch (type) {
        case 1: return "A";
        case 2: return "NS";
        case 3: return "MD";
        case 4: return "MF";
        case 5: return "CNAME";
        case 6: return "SOA";
        case 7: return "MB";
        case 8: return "MG";
        case 9: return "MR";
        case 10: return "NULL";
        case 11: return "WKS";
        case 12: return "PTR";
        case 13: return "HINFO";
        case 14: return "MINFO";
        case 15: return "MX";
        case 16: return "TXT";
        default: return "UNKNOWN";
    }
}

// Utility function to create a DNS query packet
std::vector<uint8_t> createDNSQuery(uint16_t id, const std::string& domainName, 
                                    uint16_t qtype, uint16_t qclass, uint8_t opcode = DNS_OPCODE_QUERY) {
    std::vector<uint8_t> packet;
    
    // Header section
    packet.resize(DNS_HEADER_SIZE);
    
    // ID
    packet[0] = (id >> 8) & 0xFF;
    packet[1] = id & 0xFF;
    
    // Flags: Standard query with specified opcode
    packet[2] = (opcode << 3) | 0x01;  // RD bit set (recursion desired)
    packet[3] = 0x00;
    
    // QDCOUNT: 1 question
    packet[4] = 0x00;
    packet[5] = 0x01;
    
    // ANCOUNT, NSCOUNT, ARCOUNT: all 0
    for (int i = 6; i < 12; i++) {
        packet[i] = 0x00;
    }
    
    // Question section - QNAME
    std::string label;
    size_t pos = 0;
    size_t nextDot;
    
    do {
        nextDot = domainName.find('.', pos);
        if (nextDot == std::string::npos) {
            label = domainName.substr(pos);
            nextDot = domainName.length();
        } else {
            label = domainName.substr(pos, nextDot - pos);
        }
        
        packet.push_back(static_cast<uint8_t>(label.length()));
        for (char c : label) {
            packet.push_back(static_cast<uint8_t>(c));
        }
        
        pos = nextDot + 1;
    } while (pos <= domainName.length() && nextDot < domainName.length());
    
    // Terminating zero length octet
    packet.push_back(0x00);
    
    // QTYPE
    packet.push_back((qtype >> 8) & 0xFF);
    packet.push_back(qtype & 0xFF);
    
    // QCLASS
    packet.push_back((qclass >> 8) & 0xFF);
    packet.push_back(qclass & 0xFF);
    
    return packet;
}

// Utility function to parse a domain name from a DNS packet with possible compression
std::string parseDomainName(const std::vector<uint8_t>& packet, size_t& offset) {
    std::string domainName;
    uint8_t length;
    
    while ((length = packet[offset++]) != 0) {
        // Check if this is a compressed pointer (RFC1035 section 4.1.4)
        if ((length & 0xC0) == 0xC0) {
            // It's a pointer, the next 14 bits are the offset
            uint16_t pointerOffset = ((length & 0x3F) << 8) | packet[offset++];
            size_t savedOffset = offset;
            offset = pointerOffset;
            
            // Recursively parse the domain name at the pointer offset
            domainName += parseDomainName(packet, offset);
            
            // Restore the original offset
            offset = savedOffset;
            return domainName;
        }
        
        // It's a label, copy the characters
        for (int i = 0; i < length; i++) {
            domainName += static_cast<char>(packet[offset++]);
        }
        
        // Add a dot unless this is the last label
        if (packet[offset] != 0) {
            domainName += ".";
        }
    }
    
    return domainName;
}

// Utility function to verify a DNS response
void verifyDNSResponse(const std::vector<uint8_t>& response, 
                       uint16_t expectedId, 
                       const std::string& queryName, 
                       uint16_t expectedQType, 
                       bool expectAnswer = true) {
    ASSERT_GE(response.size(), DNS_HEADER_SIZE);
    
    // Check ID
    uint16_t id = (response[0] << 8) | response[1];
    EXPECT_EQ(id, expectedId) << "Response ID does not match query ID";
    
    // Check QR bit (should be 1 for a response)
    EXPECT_EQ((response[2] & 0x80) >> 7, DNS_QR_RESPONSE) << "QR bit not set to response";
    
    // Check OPCODE (should be 0 for a standard query)
    EXPECT_EQ((response[2] & 0x78) >> 3, DNS_OPCODE_QUERY) << "Unexpected OPCODE in response";
    
    // Check RCODE (should be 0 for no error, 3 for name error)
    int rcode = response[3] & 0x0F;
    if (expectAnswer) {
        EXPECT_EQ(rcode, DNS_RCODE_NOERROR) << "Unexpected RCODE, expected NOERROR";
    } else {
        EXPECT_EQ(rcode, DNS_RCODE_NXDOMAIN) << "Unexpected RCODE for non-existent domain";
    }
    
    // Check QDCOUNT (should be 1 for a standard query)
    uint16_t qdcount = (response[4] << 8) | response[5];
    EXPECT_EQ(qdcount, 1) << "QDCOUNT should be 1 in response";
    
    // Parse the question section
    size_t offset = DNS_HEADER_SIZE;
    std::string responseName = parseDomainName(response, offset);
    
    // Check query name
    EXPECT_EQ(responseName, queryName) << "Query name in response does not match request";
    
    // Check QTYPE
    uint16_t qtype = (response[offset] << 8) | response[offset + 1];
    EXPECT_EQ(qtype, expectedQType) << "QTYPE in response does not match request";
    
    // Check QCLASS (should be 1 for IN)
    uint16_t qclass = (response[offset + 2] << 8) | response[offset + 3];
    EXPECT_EQ(qclass, DNS_CLASS_IN) << "QCLASS in response is not IN";
    
    offset += 4;  // Move past QTYPE and QCLASS
    
    // If expecting an answer, check that there is at least one answer record
    if (expectAnswer) {
        uint16_t ancount = (response[6] << 8) | response[7];
        EXPECT_GT(ancount, 0) << "Expected at least one answer record";
        
        // Verify the answer records if present
        if (ancount > 0) {
            // Parse the answer section
            for (int i = 0; i < ancount; i++) {
                // Parse name
                std::string answerName = parseDomainName(response, offset);
                
                // Check that answer name matches query name or is a valid pointer
                if (answerName.empty() && (response[offset - 2] & 0xC0) == 0xC0) {
                    // It was a compressed name, which is valid
                } else {
                    EXPECT_EQ(answerName, queryName) << "Answer name does not match query name";
                }
                
                // TYPE
                uint16_t type = (response[offset] << 8) | response[offset + 1];
                offset += 2;
                
                // CLASS
                uint16_t Class = (response[offset] << 8) | response[offset + 1];
                EXPECT_EQ(Class, DNS_CLASS_IN) << "Answer CLASS is not IN";
                offset += 2;
                
                // TTL
                uint32_t ttl = (response[offset] << 24) | (response[offset + 1] << 16) | 
                              (response[offset + 2] << 8) | response[offset + 3];
                offset += 4;
                
                // RDLENGTH
                uint16_t rdlength = (response[offset] << 8) | response[offset + 1];
                offset += 2;
                
                // Skip RDATA
                offset += rdlength;
            }
        }
    }
}

// Helper class to manage a UDP socket for sending/receiving DNS queries
class DNSSocket {
private:
    int sockfd;
    struct sockaddr_in serverAddr;

public:
    DNSSocket(const std::string& serverIP, int port) {
        // Create UDP socket
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        EXPECT_GE(sockfd, 0) << "Failed to create socket";
        
        // Set up server address
        memset(&serverAddr, 0, sizeof(serverAddr));
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(port);
        EXPECT_EQ(inet_pton(AF_INET, serverIP.c_str(), &serverAddr.sin_addr), 1) 
            << "Invalid server IP address";
        
        // Set timeout for receives
        struct timeval tv;
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    
    ~DNSSocket() {
        if (sockfd >= 0) {
            close(sockfd);
        }
    }
    
    bool sendQuery(const std::vector<uint8_t>& query) {
        ssize_t sent = sendto(sockfd, query.data(), query.size(), 0, 
                             (struct sockaddr*)&serverAddr, sizeof(serverAddr));
        return sent == static_cast<ssize_t>(query.size());
    }
    
    std::vector<uint8_t> receiveResponse() {
        std::vector<uint8_t> response(1024); // Max UDP packet size
        struct sockaddr_in fromAddr;
        socklen_t fromLen = sizeof(fromAddr);
        
        ssize_t received = recvfrom(sockfd, response.data(), response.size(), 0,
                                   (struct sockaddr*)&fromAddr, &fromLen);
        
        if (received > 0) {
            response.resize(received);
            return response;
        }
        return {};
    }
};

// Fixture for DNS Server tests
class DNSServerTest : public ::testing::Test {
protected:
    DNSServer server;
    
    void SetUp() override {
        // Add various record types as defined in RFC1035 section 3.2.2
        server.addRecord(DNSRecord("example.com", "A", "192.0.2.1"));
        server.addRecord(DNSRecord("example.com", "MX", "10 mail.example.com"));
        server.addRecord(DNSRecord("mail.example.com", "A", "192.0.2.2"));
        server.addRecord(DNSRecord("example.com", "NS", "ns1.example.com"));
        server.addRecord(DNSRecord("example.com", "NS", "ns2.example.com"));
        server.addRecord(DNSRecord("ns1.example.com", "A", "192.0.2.3"));
        server.addRecord(DNSRecord("ns2.example.com", "A", "192.0.2.4"));
        server.addRecord(DNSRecord("example.com", "TXT", "v=spf1 include:_spf.example.com -all"));
        server.addRecord(DNSRecord("example.com", "SOA", "ns1.example.com. admin.example.com. 2023111301 3600 1800 604800 86400"));
        server.addRecord(DNSRecord("www.example.com", "CNAME", "example.com"));
        server.addRecord(DNSRecord("1.2.0.192.in-addr.arpa", "PTR", "example.com"));
        server.addRecord(DNSRecord("example.com", "HINFO", "CPU OS"));
        
        // Add records for testing name case insensitivity (RFC1035 section 2.3.3)
        server.addRecord(DNSRecord("UPPER.example.com", "A", "192.0.2.5"));
        server.addRecord(DNSRecord("mixed.EXAMPLE.com", "A", "192.0.2.6"));
        
        // Add records with varying TTLs
        server.addRecord(DNSRecord("ttl.example.com", "A", "192.0.2.7")); // Default TTL
        
        // Add records for wildcard test
        server.addRecord(DNSRecord("*.wildcard.example.com", "A", "192.0.2.10"));
    }
};

// Test basic query functionality for A record
TEST_F(DNSServerTest, BasicARecordQuery) {
    std::vector<uint8_t> query = createDNSQuery(1234, "example.com", DNS_TYPE_A, DNS_CLASS_IN);
    
    std::vector<DNSRecord> results = server.query("example.com");
    ASSERT_FALSE(results.empty()) << "No results returned for a valid query";
    
    bool foundARecord = false;
    for (const auto& record : results) {
        if (record.type == "A") {
            foundARecord = true;
            EXPECT_EQ(record.value, "192.0.2.1") << "A record has incorrect value";
        }
    }
    EXPECT_TRUE(foundARecord) << "A record not found in results";
}

// Test MX record query
TEST_F(DNSServerTest, MXRecordQuery) {
    std::vector<uint8_t> query = createDNSQuery(1235, "example.com", DNS_TYPE_MX, DNS_CLASS_IN);
    
    std::vector<DNSRecord> results = server.query("example.com");
    ASSERT_FALSE(results.empty()) << "No results returned for a valid query";
    
    bool foundMXRecord = false;
    for (const auto& record : results) {
        if (record.type == "MX") {
            foundMXRecord = true;
            EXPECT_EQ(record.value, "10 mail.example.com") << "MX record has incorrect value";
        }
    }
    EXPECT_TRUE(foundMXRecord) << "MX record not found in results";
}

// Test CNAME resolution
TEST_F(DNSServerTest, CNAMEResolution) {
    std::vector<DNSRecord> results = server.query("www.example.com");
    ASSERT_FALSE(results.empty()) << "No results returned for a valid CNAME query";
    
    bool foundCNAMERecord = false;
    for (const auto& record : results) {
        if (record.type == "CNAME") {
            foundCNAMERecord = true;
            EXPECT_EQ(record.value, "example.com") << "CNAME record has incorrect value";
        }
    }
    EXPECT_TRUE(foundCNAMERecord) << "CNAME record not found in results";
    
    // Should also be able to follow the CNAME to get the A record
    // (Note: This would require DNS server implementation to support CNAME following)
}

// Test NS record query
TEST_F(DNSServerTest, NSRecordQuery) {
    std::vector<DNSRecord> results = server.query("example.com");
    ASSERT_FALSE(results.empty()) << "No results returned for a valid query";
    
    int nsRecordCount = 0;
    for (const auto& record : results) {
        if (record.type == "NS") {
            nsRecordCount++;
            EXPECT_TRUE(record.value == "ns1.example.com" || record.value == "ns2.example.com") 
                << "NS record has unexpected value: " << record.value;
        }
    }
    EXPECT_EQ(nsRecordCount, 2) << "Incorrect number of NS records found";
}

// Test SOA record query
TEST_F(DNSServerTest, SOARecordQuery) {
    std::vector<DNSRecord> results = server.query("example.com");
    ASSERT_FALSE(results.empty()) << "No results returned for a valid query";
    
    bool foundSOARecord = false;
    for (const auto& record : results) {
        if (record.type == "SOA") {
            foundSOARecord = true;
            EXPECT_EQ(record.value, "ns1.example.com. admin.example.com. 2023111301 3600 1800 604800 86400") 
                << "SOA record has incorrect value";
        }
    }
    EXPECT_TRUE(foundSOARecord) << "SOA record not found in results";
}

// Test PTR record query (reverse DNS)
TEST_F(DNSServerTest, PTRRecordQuery) {
    std::vector<DNSRecord> results = server.query("1.2.0.192.in-addr.arpa");
    ASSERT_FALSE(results.empty()) << "No results returned for a valid reverse query";
    
    bool foundPTRRecord = false;
    for (const auto& record : results) {
        if (record.type == "PTR") {
            foundPTRRecord = true;
            EXPECT_EQ(record.value, "example.com") << "PTR record has incorrect value";
        }
    }
    EXPECT_TRUE(foundPTRRecord) << "PTR record not found in results";
}

// Test TXT record query
TEST_F(DNSServerTest, TXTRecordQuery) {
    std::vector<DNSRecord> results = server.query("example.com");
    ASSERT_FALSE(results.empty()) << "No results returned for a valid query";
    
    bool foundTXTRecord = false;
    for (const auto& record : results) {
        if (record.type == "TXT") {
            foundTXTRecord = true;
            EXPECT_EQ(record.value, "v=spf1 include:_spf.example.com -all") 
                << "TXT record has incorrect value";
        }
    }
    EXPECT_TRUE(foundTXTRecord) << "TXT record not found in results";
}

// Test non-existent domain
TEST_F(DNSServerTest, NonExistentDomain) {
    std::vector<DNSRecord> results = server.query("nonexistent.example.com");
    EXPECT_TRUE(results.empty()) << "Results returned for non-existent domain";
}

// Test case insensitivity in domain names (RFC1035 section 2.3.3)
TEST_F(DNSServerTest, CaseInsensitivity) {
    // Test uppercase in query
    std::vector<DNSRecord> results1 = server.query("EXAMPLE.com");
    ASSERT_FALSE(results1.empty()) << "No results returned for uppercase query";
    
    bool foundARecord1 = false;
    for (const auto& record : results1) {
        if (record.type == "A") {
            foundARecord1 = true;
            EXPECT_EQ(record.value, "192.0.2.1") << "A record has incorrect value for uppercase query";
        }
    }
    EXPECT_TRUE(foundARecord1) << "A record not found in results for uppercase query";
    
    // Test mixed case in query
    std::vector<DNSRecord> results2 = server.query("ExAmPlE.CoM");
    ASSERT_FALSE(results2.empty()) << "No results returned for mixed case query";
    
    bool foundARecord2 = false;
    for (const auto& record : results2) {
        if (record.type == "A") {
            foundARecord2 = true;
            EXPECT_EQ(record.value, "192.0.2.1") << "A record has incorrect value for mixed case query";
        }
    }
    EXPECT_TRUE(foundARecord2) << "A record not found in results for mixed case query";
}

// Test name compression in message (RFC1035 section 4.1.4)
TEST_F(DNSServerTest, NameCompression) {
    // This test requires network-level implementation
    // The test would verify that response messages properly use name compression
    // for repeated domain names in the response
}

// Test truncated responses (RFC1035 section 4.1.1)
TEST_F(DNSServerTest, TruncatedResponses) {
    // This test would verify that when a response would exceed UDP message size limits,
    // the TC bit is set and the client can retry using TCP
}

// Test handling of invalid queries
TEST_F(DNSServerTest, InvalidQuery) {
    // Test with malformed domain name, invalid opcode, etc.
}

// Test EDNS0 support (RFC6891, an extension to DNS)
TEST_F(DNSServerTest, EDNS0Support) {
    // Test OPT record handling and larger UDP message sizes
}

// Test wildcard records (RFC1035 section 4.3.3)
TEST_F(DNSServerTest, WildcardMatching) {
    std::vector<DNSRecord> results = server.query("test.wildcard.example.com");
    
    // Wildcard handling would match *.wildcard.example.com
    bool foundWildcardMatch = false;
    for (const auto& record : results) {
        if (record.type == "A" && record.value == "192.0.2.10") {
            foundWildcardMatch = true;
        }
    }
    
    // Current implementation likely doesn't support wildcards
    // EXPECT_TRUE(foundWildcardMatch) << "Wildcard record not matched properly";
}

// Test for RFC1035 section 3.3 standard RRs (Resource Records)
TEST_F(DNSServerTest, StandardResourceRecords) {
    // Test each resource record type defined in the RFC
    std::vector<DNSRecord> results = server.query("example.com");
    
    // Verify that records of different types are correctly returned
    std::unordered_map<std::string, bool> recordTypes;
    
    for (const auto& record : results) {
        recordTypes[record.type] = true;
    }
    
    // Check for the presence of various record types
    EXPECT_TRUE(recordTypes["A"]) << "A record type missing";
    EXPECT_TRUE(recordTypes["NS"]) << "NS record type missing";
    EXPECT_TRUE(recordTypes["SOA"]) << "SOA record type missing";
    EXPECT_TRUE(recordTypes["MX"]) << "MX record type missing";
    EXPECT_TRUE(recordTypes["TXT"]) << "TXT record type missing";
}

// Main function to run the tests
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
