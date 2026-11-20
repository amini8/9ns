#pragma once

// Wire-level fixtures shared by the offline DNS tests. Pure byte builders only:
// no network, no ProgramData, no adapters.

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include "core/DnsMessage.h"

namespace testdns {

inline void appendU16(dns::Bytes& out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value & 0xFF));
}

inline void appendU32(dns::Bytes& out, uint32_t value) {
    appendU16(out, static_cast<uint16_t>(value >> 16));
    appendU16(out, static_cast<uint16_t>(value & 0xFFFF));
}

inline void appendName(dns::Bytes& out, const std::string& name) {
    size_t start = 0;
    while (start < name.size()) {
        size_t dot = name.find('.', start);
        if (dot == std::string::npos) {
            dot = name.size();
        }
        out.push_back(static_cast<uint8_t>(dot - start));
        out.insert(out.end(), name.begin() + static_cast<std::ptrdiff_t>(start),
                   name.begin() + static_cast<std::ptrdiff_t>(dot));
        start = dot + 1;
    }
    out.push_back(0);
}

inline uint32_t nowUnix() {
    return static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
}

// Builds a one-question standard query, optionally with an OPT RR carrying the
// given RDATA options (e.g. an ECS option from makeEcsOption).
inline dns::Bytes makeQuery(uint16_t id, const std::string& name, uint16_t type,
                            uint16_t qclass = 1, bool cd = false, bool withOpt = false,
                            uint16_t payloadSize = 1232, bool doBit = false,
                            const dns::Bytes& optRdata = {}) {
    dns::Bytes query;
    appendU16(query, id);
    appendU16(query, static_cast<uint16_t>(0x0100 | (cd ? 0x0010 : 0x0000)));
    appendU16(query, 1);  // 1 question
    appendU16(query, 0);  // 0 answers
    appendU16(query, 0);  // 0 authorities
    appendU16(query, withOpt ? 1 : 0);  // 0 or 1 additional
    appendName(query, name);
    appendU16(query, type);
    appendU16(query, qclass);
    if (withOpt) {
        query.push_back(0);             // OPT root name
        appendU16(query, 41);           // type OPT
        appendU16(query, payloadSize);  // class = UDP payload size
        appendU32(query, doBit ? 0x00008000u : 0u);  // TTL with the DO flag
        appendU16(query, static_cast<uint16_t>(optRdata.size()));
        query.insert(query.end(), optRdata.begin(), optRdata.end());
    }
    return query;
}

// ECS EDNS option (code 8) for an IPv4 address with the given scope prefix length.
inline dns::Bytes makeEcsOption(uint8_t scope, const dns::Bytes& addr4) {
    dns::Bytes option;
    appendU16(option, 8);  // option code ECS
    appendU16(option, static_cast<uint16_t>(4 + addr4.size()));
    appendU16(option, 1);     // family: IPv4
    option.push_back(24);     // source prefix length
    option.push_back(scope);  // scope prefix length
    option.insert(option.end(), addr4.begin(), addr4.end());
    return option;
}

// Builds a NOERROR response echoing the query's question with one answer record.
inline dns::Bytes makeAnswerResponse(const dns::Bytes& query, const dns::Query& parsed,
                                     uint16_t type, const dns::Bytes& rdata, bool ad = false) {
    dns::Bytes response;
    appendU16(response, parsed.id);
    appendU16(response, static_cast<uint16_t>(0x8000 | 0x0080 | (ad ? 0x0020 : 0x0000)));
    appendU16(response, 1);  // 1 question
    appendU16(response, 1);  // 1 answer
    appendU16(response, 0);
    appendU16(response, 0);
    response.insert(response.end(),
                    query.begin() + static_cast<std::ptrdiff_t>(dns::kHeaderSize),
                    query.begin() + static_cast<std::ptrdiff_t>(parsed.questionEnd));
    response.push_back(0xC0);
    response.push_back(0x0C);
    appendU16(response, type);
    appendU16(response, 1);     // class IN
    appendU32(response, 300);   // TTL
    appendU16(response, static_cast<uint16_t>(rdata.size()));
    response.insert(response.end(), rdata.begin(), rdata.end());
    return response;
}

// RRSIG RDATA covering an A record with the given signature validity window.
inline dns::Bytes makeRrsigRdata(uint32_t expiration, uint32_t inception) {
    dns::Bytes rdata;
    appendU16(rdata, 1);     // type covered: A
    rdata.push_back(13);     // algorithm: ECDSAP256SHA256
    rdata.push_back(2);      // labels
    appendU32(rdata, 300);   // original TTL
    appendU32(rdata, expiration);
    appendU32(rdata, inception);
    appendU16(rdata, 1234);  // key tag
    return rdata;
}

}  // namespace testdns
