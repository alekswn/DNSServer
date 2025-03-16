#include "dns_server.h"
#include <iostream>

int main() {
    DNSServer server;
    server.addRecord(DNSRecord("example.com", "A", "192.0.2.1"));
    server.addRecord(DNSRecord("example.com", "MX", "mail.example.com"));

    std::vector<DNSRecord> results = server.query("example.com");
    for (const auto& record : results) {
        std::cout << record.name << " " << record.type << " " << record.value << std::endl;
    }

    return 0;
}
