#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace dns {

using Bytes = std::vector<uint8_t>;

constexpr size_t kHeaderSize = 12;

constexpr uint8_t kRcodeNoError = 0;
constexpr uint8_t kRcodeFormErr = 1;
constexpr uint8_t kRcodeServFail = 2;
constexpr uint8_t kRcodeNxDomain = 3;
constexpr uint8_t kRcodeNotImp = 4;
constexpr uint8_t kRcodeRefused = 5;

constexpr uint16_t kTypeA = 1;
constexpr uint16_t kTypeNs = 2;
constexpr uint16_t kTypeCname = 5;
constexpr uint16_t kTypeSoa = 6;
constexpr uint16_t kTypePtr = 12;
constexpr uint16_t kTypeMx = 15;
constexpr uint16_t kTypeTxt = 16;
constexpr uint16_t kTypeAaaa = 28;
constexpr uint16_t kTypeSrv = 33;
constexpr uint16_t kTypeOpt = 41;
constexpr uint16_t kTypeDs = 43;
constexpr uint16_t kTypeRrsig = 46;
constexpr uint16_t kTypeNsec = 47;
constexpr uint16_t kTypeDnskey = 48;
constexpr uint16_t kTypeNsec3 = 50;
constexpr uint16_t kTypeAny = 255;

struct Query {
    uint16_t id = 0;
    std::string name;        // lower case, no trailing dot; empty for the root
    uint16_t type = 0;
    uint16_t qclass = 0;
    size_t questionEnd = 0;  // offset just past the question section
};

struct TtlField {
    size_t offset = 0;       // offset of the 4-byte TTL field
    uint16_t type = 0;
    uint32_t ttl = 0;
};

// Cache-partitioning context of a query: the header flags and OPT RR fields that
// make two queries non-equivalent for reply-cache purposes.
struct QueryContext {
    bool cd = false;
    bool doBit = false;
    bool hasOpt = false;
    uint16_t ednsPayloadSize = 0;
    uint64_t ednsOptionsHash = 0;  // FNV-1a of the OPT RDATA (ECS scope, cookies, ...)
};

struct Record {
    std::string name;
    uint16_t type = 0;
    uint16_t rclass = 0;
    uint32_t ttl = 0;
    std::string dataFormatted;
    Bytes rdata;
};

struct ParsedMessage {
    uint16_t id = 0;
    bool isResponse = false;
    bool aa = false;
    bool tc = false;
    bool rd = false;
    bool ra = false;
    bool ad = false;
    bool cd = false;
    uint8_t rcode = 0;
    std::vector<Query> questions;
    std::vector<Record> answers;
    std::vector<Record> authorities;
    std::vector<Record> additionals;
};

// Parses a standard query with exactly one question.
bool parseQuery(const Bytes& packet, Query& out);

// Reads the cache-partitioning context (CD/DO flags and OPT RR fields) from a query.
bool queryContext(const Bytes& packet, const Query& parsed, QueryContext& out);

// Parses a complete DNS message (header, questions, answers, authorities, additionals).
bool parseMessage(const Bytes& packet, ParsedMessage& out);

// Builds a reply with the query's id and question, the given rcode, and no records.
Bytes makeErrorResponse(const Bytes& query, const Query& parsed, uint8_t rcode);

// Builds a blocked reply returning 0.0.0.0 (A) or :: (AAAA) with NOERROR.
Bytes makeNullIpResponse(const Bytes& query, const Query& parsed);

// Builds a local reply returning a static IP.
Bytes makeLocalIpResponse(const Bytes& query, const Query& parsed, const std::string& ip);

// True if the packet is a response carrying the given id.
bool isResponseFor(const Bytes& packet, uint16_t id);

// True if the packet is a response carrying the query's id and echoing its
// question (QNAME/QTYPE/QCLASS). Use this when accepting upstream replies.
// The id-only form above stays for wire paths that rewrite ids (e.g. DoQ).
bool isResponseFor(const Bytes& packet, const Bytes& query);

// Reads the rcode from a response header. Returns false if the packet is too short.
bool responseCode(const Bytes& packet, uint8_t& rcode);

// Lists the TTL field of every answer, authority and additional record.
bool collectTtls(const Bytes& packet, std::vector<TtlField>& out);

bool hasAdBit(const Bytes& packet);

void setId(Bytes& packet, uint16_t id);
void setTtl(Bytes& packet, size_t offset, uint32_t ttl);

std::string typeName(uint16_t type);
std::string rcodeName(uint8_t rcode);

}  // namespace dns
