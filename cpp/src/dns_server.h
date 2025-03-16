#ifndef DNS_SERVER_H
#define DNS_SERVER_H

#include <string>
#include <unordered_map>
#include <vector>

class DNSRecord {
public:
    std::string name;
    std::string type;
    std::string value;

    DNSRecord(const std::string& n, const std::string& t, const std::string& v)
        : name(n), type(t), value(v) {}
};

class DNSServer {
private:
    std::unordered_map<std::string, std::vector<DNSRecord>> records;

public:
    void addRecord(const DNSRecord& record);
    std::vector<DNSRecord> query(const std::string& name);
};

#endif // DNS_SERVER_H
