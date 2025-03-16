#ifndef DNS_SERVER_H
#define DNS_SERVER_H

#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <span>
#include <concepts>
#include <functional>
#include <stdexcept>
#include <compare>
#include <type_traits>

// Enumeration for common DNS record types with string view conversion
enum class RecordType {
    A,
    AAAA,
    CNAME,
    MX,
    NS,
    PTR,
    SOA,
    TXT,
    HINFO,
    Unknown
};

// Convert RecordType to string_view
constexpr std::string_view to_string_view(RecordType type) {
    switch (type) {
        case RecordType::A:     return "A";
        case RecordType::AAAA:  return "AAAA";
        case RecordType::CNAME: return "CNAME";
        case RecordType::MX:    return "MX";
        case RecordType::NS:    return "NS";
        case RecordType::PTR:   return "PTR";
        case RecordType::SOA:   return "SOA";
        case RecordType::TXT:   return "TXT";
        case RecordType::HINFO: return "HINFO";
        case RecordType::Unknown: 
        default:                return "Unknown";
    }
}

// Parse string_view to RecordType
constexpr RecordType parse_record_type(std::string_view type_str) {
    if (type_str == "A")     return RecordType::A;
    if (type_str == "AAAA")  return RecordType::AAAA;
    if (type_str == "CNAME") return RecordType::CNAME;
    if (type_str == "MX")    return RecordType::MX;
    if (type_str == "NS")    return RecordType::NS;
    if (type_str == "PTR")   return RecordType::PTR;
    if (type_str == "SOA")   return RecordType::SOA;
    if (type_str == "TXT")   return RecordType::TXT;
    if (type_str == "HINFO") return RecordType::HINFO;
    return RecordType::Unknown;
}

class DNSRecord {
public:
    std::string name;
    std::string type;
    std::string value;
    
    // C++20 designated initializers in constructor
    DNSRecord(std::string_view n, std::string_view t, std::string_view v)
        : name{std::string(n)}, type{std::string(t)}, value{std::string(v)} {}
    
    // Constructor with RecordType enum
    DNSRecord(std::string_view n, RecordType t, std::string_view v)
        : name{std::string(n)}, type{std::string(to_string_view(t))}, value{std::string(v)} {}

    // C++20 default comparison operators (<=>) for easy sorting and comparison
    auto operator<=>(const DNSRecord&) const = default;
};

class DNSServer {
private:
    // Standard unordered_map without the custom comparator for now
    std::unordered_map<std::string, std::vector<DNSRecord>> records;

public:
    // Mark functions that shouldn't have their return values ignored
    [[nodiscard]] 
    bool empty() const noexcept {
        return records.empty();
    }
    
    // Add record with string_view parameters
    void addRecord(const DNSRecord& record);
    
    // Modern overload with string_view
    void addRecord(std::string_view name, std::string_view type, std::string_view value) {
        addRecord(DNSRecord{name, type, value});
    }
    
    // Modern overload with RecordType enum
    void addRecord(std::string_view name, RecordType type, std::string_view value) {
        addRecord(DNSRecord{name, type, value});
    }
    
    // Query with string_view for better performance
    [[nodiscard]]
    std::vector<DNSRecord> query(std::string_view name) const;
    
    // Query by type overload for strings
    [[nodiscard]]
    std::vector<DNSRecord> queryByType(std::string_view name, std::string_view type) const {
        auto results = query(name);
        std::vector<DNSRecord> filtered;
        for (const auto& record : results) {
            if (record.type == type) {
                filtered.push_back(record);
            }
        }
        return filtered;
    }
    
    // Query by type overload for RecordType enum
    [[nodiscard]]
    std::vector<DNSRecord> queryByType(std::string_view name, RecordType type) const {
        return queryByType(name, to_string_view(type));
    }
};

// Helpers for DNS packet parsing using std::span
namespace dns_packet {
    // Span-based DNS packet reader
    class PacketReader {
    private:
        std::span<const uint8_t> data;
        size_t position = 0;
        
    public:
        explicit PacketReader(std::span<const uint8_t> packet_data) 
            : data(packet_data) {}
            
        [[nodiscard]]
        uint8_t readUint8() {
            if (position >= data.size()) throw std::out_of_range("Packet buffer overrun");
            return data[position++];
        }
        
        [[nodiscard]]
        uint16_t readUint16() {
            if (position + 1 >= data.size()) throw std::out_of_range("Packet buffer overrun");
            uint16_t value = (static_cast<uint16_t>(data[position]) << 8) | data[position + 1];
            position += 2;
            return value;
        }
        
        [[nodiscard]]
        std::span<const uint8_t> readBytes(size_t length) {
            if (position + length > data.size()) throw std::out_of_range("Packet buffer overrun");
            auto result = data.subspan(position, length);
            position += length;
            return result;
        }
        
        [[nodiscard]]
        std::string readDomainName();
    };
}

#endif // DNS_SERVER_H
