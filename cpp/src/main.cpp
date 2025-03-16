#include "dns_server.h"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <csignal>
#include <thread>
#include <atomic>
#include <span>
#include <vector>

constexpr uint16_t DNS_PORT = 5353;  // Using a non-privileged port instead of 53
constexpr int MAX_DNS_PACKET_SIZE = 512;  // Standard DNS UDP packet size
std::atomic<bool> running{true};

// Signal handler to gracefully shutdown the server
void signalHandler(int signum) {
    std::cout << "\nReceived signal " << signum << ". Shutting down..." << std::endl;
    running = false;
}

// Function to parse domain name from a DNS query
std::string parseDomainName(std::span<const uint8_t> packet, size_t& offset) {
    std::string domainName;
    
    while (true) {
        uint8_t labelLength = packet[offset++];
        if (labelLength == 0) {
            break;  // End of domain name
        }
        
        // Handle DNS message compression (RFC1035 section 4.1.4)
        if ((labelLength & 0xC0) == 0xC0) {
            // Compression pointer
            uint16_t pointer = ((labelLength & 0x3F) << 8) | packet[offset++];
            size_t savedOffset = offset;
            offset = pointer;
            domainName += parseDomainName(packet, offset);
            offset = savedOffset;
            return domainName;
        }
        
        // Regular label
        if (!domainName.empty()) {
            domainName += ".";
        }
        
        for (int i = 0; i < labelLength; i++) {
            domainName += packet[offset++];
        }
    }
    
    return domainName;
}

// Function to encode a domain name in DNS format
std::vector<uint8_t> encodeDomainName(const std::string& domain) {
    std::vector<uint8_t> result;
    std::string label;
    
    for (char c : domain) {
        if (c == '.') {
            result.push_back(static_cast<uint8_t>(label.size()));
            for (char lc : label) {
                result.push_back(static_cast<uint8_t>(lc));
            }
            label.clear();
        } else {
            label += c;
        }
    }
    
    // Add the last label if any
    if (!label.empty()) {
        result.push_back(static_cast<uint8_t>(label.size()));
        for (char lc : label) {
            result.push_back(static_cast<uint8_t>(lc));
        }
    }
    
    // End with a zero length label
    result.push_back(0);
    
    return result;
}

// Function to create a DNS response
std::vector<uint8_t> createDNSResponse(const std::span<const uint8_t> query, const DNSServer& server) {
    std::vector<uint8_t> response(query.begin(), query.end());
    
    // Set QR bit to 1 (response) and clear other flags
    response[2] = 0x80; // QR=1, other flags 0
    response[3] = 0x00; // Clear all flags
    
    // Parse the question
    size_t offset = 12;  // Skip header
    std::string domainName = parseDomainName(query, offset);
    
    // Get qtype and qclass
    uint16_t qtype = (query[offset] << 8) | query[offset + 1];
    offset += 4;  // Skip qtype (2) and qclass (2)
    
    // Get matching records
    std::vector<DNSRecord> records;
    if (qtype == 255) {  // ANY
        records = server.query(domainName);
    } else {
        // Convert qtype to string representation
        std::string typeStr;
        switch (qtype) {
            case 1: typeStr = "A"; break;
            case 2: typeStr = "NS"; break;
            case 5: typeStr = "CNAME"; break;
            case 6: typeStr = "SOA"; break;
            case 12: typeStr = "PTR"; break;
            case 15: typeStr = "MX"; break;
            case 16: typeStr = "TXT"; break;
            default: typeStr = "A"; break;
        }
        records = server.queryByType(domainName, typeStr);
    }
    
    // Set answer count
    uint16_t answerCount = records.size();
    response[6] = answerCount >> 8;
    response[7] = answerCount & 0xFF;
    
    // Check if we need to set RCODE to NXDOMAIN (3) when domain doesn't exist
    if (records.empty() && server.query(domainName).empty()) {
        response[3] |= 0x03; // RCODE = 3 (NXDOMAIN)
    }
    
    // Add answer records
    // Continuing after the question section - offset holds the current position
     
    for (const auto& record : records) {
        // Add pointer to the domain name (compression)
        response.push_back(0xC0);
        response.push_back(0x0C);  // Pointer to offset 12
        
        // Add type
        uint16_t type = 1;  // Default to A
        if (record.type == "NS") type = 2;
        else if (record.type == "CNAME") type = 5;
        else if (record.type == "SOA") type = 6;
        else if (record.type == "PTR") type = 12;
        else if (record.type == "MX") type = 15;
        else if (record.type == "TXT") type = 16;
        
        response.push_back(type >> 8);
        response.push_back(type & 0xFF);
        
        // Add class (IN)
        response.push_back(0x00);
        response.push_back(0x01);
        
        // Add TTL (300 seconds)
        response.push_back(0x00);
        response.push_back(0x00);
        response.push_back(0x01);
        response.push_back(0x2C);
        
        // Add data based on the record type
        if (type == 1) {  // A record
            // Add data length for IPv4 address (4 bytes)
            response.push_back(0x00);
            response.push_back(0x04);
            
            // Convert IP address to binary
            struct in_addr addr;
            inet_pton(AF_INET, record.value.c_str(), &addr);
            response.push_back((addr.s_addr >> 0) & 0xFF);
            response.push_back((addr.s_addr >> 8) & 0xFF);
            response.push_back((addr.s_addr >> 16) & 0xFF);
            response.push_back((addr.s_addr >> 24) & 0xFF);
        } 
        else if (type == 2 || type == 5 || type == 12) {  // NS, CNAME, PTR records
            // Encode domain name
            auto encodedName = encodeDomainName(record.value);
            
            // Add data length
            response.push_back(encodedName.size() >> 8);
            response.push_back(encodedName.size() & 0xFF);
            
            // Add encoded domain name
            response.insert(response.end(), encodedName.begin(), encodedName.end());
        }
        else if (type == 15) {  // MX record
            // Parse "priority hostname" format
            size_t spacePos = record.value.find(' ');
            uint16_t priority = 10; // Default priority
            std::string hostname = record.value;
            
            if (spacePos != std::string::npos) {
                try {
                    priority = std::stoi(record.value.substr(0, spacePos));
                    hostname = record.value.substr(spacePos + 1);
                } catch (...) {
                    // Use defaults if parsing fails
                }
            }
            
            // Encode domain name
            auto encodedName = encodeDomainName(hostname);
            
            // Add data length (2 bytes for priority + encoded domain name length)
            response.push_back(0x00);
            response.push_back(static_cast<uint8_t>(2 + encodedName.size()));
            
            // Add priority
            response.push_back(priority >> 8);
            response.push_back(priority & 0xFF);
            
            // Add encoded domain name
            response.insert(response.end(), encodedName.begin(), encodedName.end());
        }
        else if (type == 16) {  // TXT record
            // For TXT records, we need to add length byte before the actual text
            std::string value = record.value;
            if (value.size() > 255) {
                value = value.substr(0, 255); // Truncate to max length
            }
            
            // Add data length
            response.push_back(0x00);
            response.push_back(static_cast<uint8_t>(value.size() + 1)); // +1 for length byte
            
            // Add text length and text
            response.push_back(static_cast<uint8_t>(value.size()));
            for (char c : value) {
                response.push_back(static_cast<uint8_t>(c));
            }
        }
        else if (type == 6) {  // SOA record
            // SOA record format: primary_ns admin_mailbox serial refresh retry expire minimum
            // Simplified: just encode as two domain names followed by 5 32-bit values
            std::string primaryNS = "ns1.example.com";
            std::string adminMailbox = "admin.example.com";
            uint32_t serial = 2023091401;
            uint32_t refresh = 3600;
            uint32_t retry = 900;
            uint32_t expire = 1209600;
            uint32_t minimum = 300;
            
            // Encode domain names
            auto encodedPrimary = encodeDomainName(primaryNS);
            auto encodedAdmin = encodeDomainName(adminMailbox);
            
            // Calculate total length
            size_t totalLength = encodedPrimary.size() + encodedAdmin.size() + 20; // 5 32-bit values = 20 bytes
            
            // Add data length
            response.push_back(totalLength >> 8);
            response.push_back(totalLength & 0xFF);
            
            // Add primary NS
            response.insert(response.end(), encodedPrimary.begin(), encodedPrimary.end());
            
            // Add admin mailbox
            response.insert(response.end(), encodedAdmin.begin(), encodedAdmin.end());
            
            // Add serial
            response.push_back((serial >> 24) & 0xFF);
            response.push_back((serial >> 16) & 0xFF);
            response.push_back((serial >> 8) & 0xFF);
            response.push_back(serial & 0xFF);
            
            // Add refresh
            response.push_back((refresh >> 24) & 0xFF);
            response.push_back((refresh >> 16) & 0xFF);
            response.push_back((refresh >> 8) & 0xFF);
            response.push_back(refresh & 0xFF);
            
            // Add retry
            response.push_back((retry >> 24) & 0xFF);
            response.push_back((retry >> 16) & 0xFF);
            response.push_back((retry >> 8) & 0xFF);
            response.push_back(retry & 0xFF);
            
            // Add expire
            response.push_back((expire >> 24) & 0xFF);
            response.push_back((expire >> 16) & 0xFF);
            response.push_back((expire >> 8) & 0xFF);
            response.push_back(expire & 0xFF);
            
            // Add minimum
            response.push_back((minimum >> 24) & 0xFF);
            response.push_back((minimum >> 16) & 0xFF);
            response.push_back((minimum >> 8) & 0xFF);
            response.push_back(minimum & 0xFF);
        }
        else {
            // For other record types, just encode as a string (fallback)
            std::string value = record.value;
            
            // Add data length
            response.push_back(0x00);
            response.push_back(static_cast<uint8_t>(value.size()));
            
            // Add data
            for (char c : value) {
                response.push_back(static_cast<uint8_t>(c));
            }
        }
    }
    
    // Check if response is too large and set TC flag if needed
    if (response.size() > MAX_DNS_PACKET_SIZE) {
        response[2] |= 0x02; // Set TC flag
        response.resize(MAX_DNS_PACKET_SIZE);
    }
    
    return response;
}

int main() {
    // Setup signal handling for graceful shutdown
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    DNSServer server;
    
    // Add test records
    server.addRecord("example.com", RecordType::A, "192.0.2.1");
    server.addRecord("example.com", RecordType::MX, "10 mail.example.com");
    server.addRecord("example.com", "TXT", "This is a test record");
    server.addRecord("example.com", "NS", "ns1.example.com");
    server.addRecord("example.com", "NS", "ns2.example.com");
    server.addRecord("example.com", "SOA", "ns1.example.com admin.example.com 2023091401 3600 900 1209600 300");
    server.addRecord("mail.example.com", RecordType::A, "192.0.2.2");
    server.addRecord("ns1.example.com", RecordType::A, "192.0.2.3");
    server.addRecord("ns2.example.com", RecordType::A, "192.0.2.4");
    server.addRecord("www.example.com", "CNAME", "example.com");
    // Add A record for www.example.com to support direct resolution
    server.addRecord("www.example.com", RecordType::A, "192.0.2.1");
    server.addRecord("test.example.com", RecordType::A, "192.0.2.5");
    // Add PTR record for reverse lookup
    server.addRecord("1.2.0.192.in-addr.arpa", "PTR", "example.com");
    
    // Create UDP socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        std::cerr << "Error opening socket" << std::endl;
        return 1;
    }
    
    // Set socket options
    int reuse = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        std::cerr << "Error setting socket options" << std::endl;
        close(sockfd);
        return 1;
    }
    
    // Bind to port
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(DNS_PORT);
    
    if (bind(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "Error binding to port " << DNS_PORT << std::endl;
        std::cerr << "Try running with sudo or use a port > 1024" << std::endl;
        close(sockfd);
        return 1;
    }
    
    std::cout << "DNS Server running on port " << DNS_PORT << "..." << std::endl;
    
    // Main server loop
    while (running) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        
        // Set timeout for select to allow checking the running flag
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int activity = select(sockfd + 1, &readfds, NULL, NULL, &tv);
        
        if (activity < 0) {
            if (errno == EINTR) {
                // Interrupted by signal, just continue
                continue;
            }
            std::cerr << "Select error" << std::endl;
            break;
        }
        
        if (activity == 0) {
            // Timeout, just continue and check running flag
            continue;
        }
        
        if (FD_ISSET(sockfd, &readfds)) {
            // Receive DNS query
            std::vector<uint8_t> buffer(MAX_DNS_PACKET_SIZE);
            struct sockaddr_in clientAddr;
            socklen_t clientLen = sizeof(clientAddr);
            
            ssize_t recvLen = recvfrom(sockfd, buffer.data(), buffer.size(), 0,
                                      (struct sockaddr*)&clientAddr, &clientLen);
            
            if (recvLen > 0) {
                buffer.resize(recvLen);
                std::span<const uint8_t> querySpan(buffer.data(), recvLen);
                
                // Create response
                std::vector<uint8_t> response = createDNSResponse(querySpan, server);
                
                // Send response back to client
                sendto(sockfd, response.data(), response.size(), 0,
                      (struct sockaddr*)&clientAddr, clientLen);
                
                // Log query details
                char clientIP[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(clientAddr.sin_addr), clientIP, INET_ADDRSTRLEN);
                std::cout << "Query from " << clientIP << ":" << ntohs(clientAddr.sin_port);
                
                // Extract query ID and domain from the query
                size_t offset = 12;  // Skip header
                std::string domainName = parseDomainName(querySpan, offset);
                
                std::cout << " for " << domainName << std::endl;
            }
        }
    }
    
    // Cleanup
    close(sockfd);
    std::cout << "DNS Server stopped" << std::endl;
    
    return 0;
}
