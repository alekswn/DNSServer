#include "dns_server.h"
#include <iostream>
#include <algorithm>

// Helper function to convert a string to lowercase
std::string toLowercase(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(),
                  [](unsigned char c) { return std::tolower(c); });
    return result;
}

void DNSServer::addRecord(const DNSRecord& record) {
    // Store record with lowercase domain name for case-insensitive lookups
    DNSRecord normalizedRecord(toLowercase(record.name), record.type, record.value);
    records[normalizedRecord.name].push_back(normalizedRecord);
}

std::vector<DNSRecord> DNSServer::query(const std::string& name) {
    // Convert query name to lowercase for case-insensitive lookups
    std::string normalizedName = toLowercase(name);
    return records[normalizedName];
}
