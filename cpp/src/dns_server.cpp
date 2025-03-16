#include "dns_server.h"
#include <iostream>
#include <algorithm>
#include <cctype>

// Helper function to convert a string to lowercase using modern C++ approaches
std::string toLowercase(std::string_view str) {
    std::string result;
    result.reserve(str.size());
    
    // Using algorithm with a lambda function, more portable than ranges for now
    std::transform(str.begin(), str.end(), std::back_inserter(result),
                  [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                  
    return result;
}

void DNSServer::addRecord(const DNSRecord& record) {
    // Store record with lowercase domain name for case-insensitive lookups
    DNSRecord normalizedRecord(toLowercase(record.name), record.type, record.value);
    records[normalizedRecord.name].push_back(normalizedRecord);
}

std::vector<DNSRecord> DNSServer::query(std::string_view name) const {
    // Convert query name to lowercase for case-insensitive lookups
    std::string normalizedName = toLowercase(name);
    
    // Look up in the map using the normalized name
    auto it = records.find(normalizedName);
    if (it != records.end()) {
        return it->second;
    }
    
    return {}; // Return empty vector if not found
}

// Implementation of DNS packet reader's readDomainName method
std::string dns_packet::PacketReader::readDomainName() {
    std::string result;
    uint8_t length = readUint8();
    
    // Handle DNS domain name compression and standard format
    while (length > 0) {
        // Check if this is a pointer (compression method)
        if ((length & 0xC0) == 0xC0) {
            // This is a pointer - the next byte plus the lower 6 bits of this byte
            // form a 14-bit offset to where the actual name is stored
            uint8_t offsetLow = readUint8();
            uint16_t offset = ((length & 0x3F) << 8) | offsetLow;
            
            // Save current position
            size_t savedPosition = position;
            
            // Jump to the offset
            position = offset;
            
            // Read the rest of the name recursively
            std::string suffix = readDomainName();
            if (!result.empty()) {
                result += ".";
            }
            result += suffix;
            
            // Restore position and exit - pointers always terminate a name
            position = savedPosition;
            return result;
        } else {
            // This is a standard label
            auto label = readBytes(length);
            
            // Convert to string and append
            if (!result.empty()) {
                result += ".";
            }
            
            // Convert bytes to string using traditional methods
            for (const auto& byte : label) {
                result += static_cast<char>(byte);
            }
            
            // Read next length byte
            length = readUint8();
        }
    }
    
    return result;
}
