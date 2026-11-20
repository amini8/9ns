#include <winsock2.h>
#include <ws2tcpip.h>

#include "core/DnsMessage.h"

#include <cstddef>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace dns {
namespace {

uint16_t readU16(const Bytes& p, size_t off) {
    return static_cast<uint16_t>((p[off] << 8) | p[off + 1]);
}

uint32_t readU32(const Bytes& p, size_t off) {
    return (static_cast<uint32_t>(p[off]) << 24) | (static_cast<uint32_t>(p[off + 1]) << 16) |
           (static_cast<uint32_t>(p[off + 2]) << 8) | static_cast<uint32_t>(p[off + 3]);
}

void writeU16(Bytes& p, size_t off, uint16_t value) {
    p[off] = static_cast<uint8_t>(value >> 8);
    p[off + 1] = static_cast<uint8_t>(value & 0xFF);
}

void writeU32(Bytes& p, size_t off, uint32_t value) {
    p[off] = static_cast<uint8_t>(value >> 24);
    p[off + 1] = static_cast<uint8_t>((value >> 16) & 0xFF);
    p[off + 2] = static_cast<uint8_t>((value >> 8) & 0xFF);
    p[off + 3] = static_cast<uint8_t>(value & 0xFF);
}

bool skipName(const Bytes& p, size_t& off) {
    for (;;) {
        if (off >= p.size()) {
            return false;
        }
        const uint8_t length = p[off];
        if ((length & 0xC0) == 0xC0) {
            if (off + 2 > p.size()) {
                return false;
            }
            off += 2;
            return true;
        }
        if ((length & 0xC0) != 0) {
            return false;
        }
        if (length == 0) {
            off += 1;
            return true;
        }
        off += 1 + static_cast<size_t>(length);
    }
}

bool readName(const Bytes& p, size_t& off, std::string& name) {
    name.clear();
    size_t cursor = off;
    bool jumped = false;
    size_t jumps = 0;

    for (;;) {
        if (cursor >= p.size()) {
            return false;
        }
        const uint8_t len = p[cursor];
        if ((len & 0xC0) == 0xC0) {
            if (cursor + 2 > p.size()) {
                return false;
            }
            if (!jumped) {
                off = cursor + 2;
                jumped = true;
            }
            cursor = ((static_cast<size_t>(len & 0x3F)) << 8) | p[cursor + 1];
            if (++jumps > 20) {
                return false; // loop detected
            }
            continue;
        }
        if ((len & 0xC0) != 0) {
            return false;
        }
        cursor++;
        if (len == 0) {
            break;
        }
        if (cursor + len > p.size()) {
            return false;
        }
        if (!name.empty()) {
            name.push_back('.');
        }
        for (size_t i = 0; i < len; ++i) {
            char c = static_cast<char>(p[cursor + i]);
            if (c >= 'A' && c <= 'Z') {
                c = static_cast<char>(c - 'A' + 'a');
            }
            name.push_back(c);
        }
        cursor += len;
    }

    if (!jumped) {
        off = cursor;
    }
    return true;
}

bool readQuestionName(const Bytes& p, size_t& off, std::string& name) {
    name.clear();
    for (;;) {
        if (off >= p.size()) {
            return false;
        }
        const uint8_t length = p[off++];
        if (length == 0) {
            return true;
        }
        if (length > 63 || off + length > p.size()) {
            return false;
        }
        if (!name.empty()) {
            name.push_back('.');
        }
        for (uint8_t i = 0; i < length; ++i) {
            char c = static_cast<char>(p[off + i]);
            if (c == '.') {
                return false;
            }
            if (c >= 'A' && c <= 'Z') {
                c = static_cast<char>(c - 'A' + 'a');
            }
            name.push_back(c);
        }
        off += length;
        if (name.size() > 253) {
            return false;
        }
    }
}

uint64_t fnv1a64(const uint8_t* data, size_t length) {
    uint64_t hash = 0xcbf29ce484222325ull;
    for (size_t i = 0; i < length; ++i) {
        hash ^= data[i];
        hash *= 0x100000001b3ull;
    }
    return hash;
}

}  // namespace

std::string typeName(uint16_t type) {
    switch (type) {
        case kTypeA: return "A";
        case kTypeNs: return "NS";
        case kTypeCname: return "CNAME";
        case kTypeSoa: return "SOA";
        case kTypePtr: return "PTR";
        case kTypeMx: return "MX";
        case kTypeTxt: return "TXT";
        case kTypeAaaa: return "AAAA";
        case kTypeSrv: return "SRV";
        case kTypeOpt: return "OPT";
        case kTypeDs: return "DS";
        case kTypeRrsig: return "RRSIG";
        case kTypeNsec: return "NSEC";
        case kTypeDnskey: return "DNSKEY";
        case kTypeNsec3: return "NSEC3";
        case kTypeAny: return "ANY";
        default: return std::to_string(type);
    }
}

std::string rcodeName(uint8_t rcode) {
    switch (rcode) {
        case kRcodeNoError: return "NOERROR";
        case kRcodeFormErr: return "FORMERR";
        case kRcodeServFail: return "SERVFAIL";
        case kRcodeNxDomain: return "NXDOMAIN";
        case kRcodeNotImp: return "NOTIMP";
        case kRcodeRefused: return "REFUSED";
        default: return "RCODE(" + std::to_string(rcode) + ")";
    }
}

bool parseQuery(const Bytes& packet, Query& out) {
    if (packet.size() < kHeaderSize) {
        return false;
    }
    const uint16_t flags = readU16(packet, 2);
    const bool isResponse = (flags & 0x8000) != 0;
    const unsigned opcode = (flags >> 11) & 0x0F;
    if (isResponse || opcode != 0 || readU16(packet, 4) != 1) {
        return false;
    }

    size_t off = kHeaderSize;
    if (!readQuestionName(packet, off, out.name) || off + 4 > packet.size()) {
        return false;
    }
    out.id = readU16(packet, 0);
    out.type = readU16(packet, off);
    out.qclass = readU16(packet, off + 2);
    out.questionEnd = off + 4;
    return true;
}

bool queryContext(const Bytes& packet, const Query& parsed, QueryContext& out) {
    out = QueryContext{};
    if (packet.size() < kHeaderSize) {
        return false;
    }
    out.cd = (readU16(packet, 2) & 0x0010) != 0;

    // Walk every record after the question to locate the OPT RR (EDNS0).
    const size_t records = static_cast<size_t>(readU16(packet, 6)) + readU16(packet, 8) +
                           readU16(packet, 10);
    size_t off = parsed.questionEnd;
    for (size_t i = 0; i < records; ++i) {
        if (!skipName(packet, off) || off + 10 > packet.size()) {
            return false;
        }
        const size_t rr = off;
        const uint16_t type = readU16(packet, rr);
        const uint32_t ttl = readU32(packet, rr + 4);
        const size_t rdlength = readU16(packet, rr + 8);
        off = rr + 10;
        if (off + rdlength > packet.size()) {
            return false;
        }
        if (type == kTypeOpt && !out.hasOpt) {
            out.hasOpt = true;
            out.ednsPayloadSize = readU16(packet, rr + 2);
            out.doBit = (ttl & 0x00008000) != 0;
            out.ednsOptionsHash = fnv1a64(packet.data() + off, rdlength);
        }
        off += rdlength;
    }
    return true;
}

bool parseMessage(const Bytes& packet, ParsedMessage& out) {
    if (packet.size() < kHeaderSize) {
        return false;
    }
    out.id = readU16(packet, 0);
    const uint16_t flags = readU16(packet, 2);
    out.isResponse = (flags & 0x8000) != 0;
    out.aa = (flags & 0x0400) != 0;
    out.tc = (flags & 0x0200) != 0;
    out.rd = (flags & 0x0100) != 0;
    out.ra = (flags & 0x0080) != 0;
    out.ad = (flags & 0x0020) != 0;
    out.cd = (flags & 0x0010) != 0;
    out.rcode = static_cast<uint8_t>(flags & 0x0F);

    const size_t qdCount = readU16(packet, 4);
    const size_t anCount = readU16(packet, 6);
    const size_t nsCount = readU16(packet, 8);
    const size_t arCount = readU16(packet, 10);

    size_t off = kHeaderSize;
    out.questions.clear();
    for (size_t i = 0; i < qdCount; ++i) {
        Query q;
        if (!readName(packet, off, q.name) || off + 4 > packet.size()) {
            return false;
        }
        q.id = out.id;
        q.type = readU16(packet, off);
        q.qclass = readU16(packet, off + 2);
        off += 4;
        q.questionEnd = off;
        out.questions.push_back(q);
    }

    auto parseRecords = [&](size_t count, std::vector<Record>& list) -> bool {
        list.clear();
        for (size_t i = 0; i < count; ++i) {
            Record r;
            if (!readName(packet, off, r.name) || off + 10 > packet.size()) {
                return false;
            }
            r.type = readU16(packet, off);
            r.rclass = readU16(packet, off + 2);
            r.ttl = readU32(packet, off + 4);
            const size_t rdlen = readU16(packet, off + 8);
            off += 10;
            if (off + rdlen > packet.size()) {
                return false;
            }
            r.rdata.assign(packet.begin() + off, packet.begin() + off + rdlen);

            if (r.type == kTypeA && rdlen == 4) {
                char ipStr[INET_ADDRSTRLEN] = {};
                inet_ntop(AF_INET, packet.data() + off, ipStr, sizeof(ipStr));
                r.dataFormatted = ipStr;
            } else if (r.type == kTypeAaaa && rdlen == 16) {
                char ipStr[INET6_ADDRSTRLEN] = {};
                inet_ntop(AF_INET6, packet.data() + off, ipStr, sizeof(ipStr));
                r.dataFormatted = ipStr;
            } else if (r.type == kTypeCname || r.type == kTypePtr || r.type == kTypeNs) {
                size_t nameOff = off;
                std::string target;
                if (readName(packet, nameOff, target)) {
                    r.dataFormatted = target;
                }
            } else {
                std::ostringstream ss;
                ss << rdlen << " bytes";
                r.dataFormatted = ss.str();
            }

            off += rdlen;
            list.push_back(r);
        }
        return true;
    };

    if (!parseRecords(anCount, out.answers) ||
        !parseRecords(nsCount, out.authorities) ||
        !parseRecords(arCount, out.additionals)) {
        return false;
    }

    return true;
}

Bytes makeErrorResponse(const Bytes& query, const Query& parsed, uint8_t rcode) {
    const uint16_t queryFlags = readU16(query, 2);
    const uint16_t flags =
        static_cast<uint16_t>(0x8000 | (queryFlags & 0x0100) | 0x0080 | (rcode & 0x0F));

    Bytes reply(kHeaderSize, 0);
    writeU16(reply, 0, parsed.id);
    writeU16(reply, 2, flags);
    writeU16(reply, 4, 1);
    reply.insert(reply.end(),
                 query.begin() + static_cast<std::ptrdiff_t>(kHeaderSize),
                 query.begin() + static_cast<std::ptrdiff_t>(parsed.questionEnd));
    return reply;
}

Bytes makeNullIpResponse(const Bytes& query, const Query& parsed) {
    if (parsed.type != kTypeA && parsed.type != kTypeAaaa) {
        return makeErrorResponse(query, parsed, kRcodeNoError);
    }

    const uint16_t queryFlags = readU16(query, 2);
    const uint16_t flags = static_cast<uint16_t>(0x8000 | (queryFlags & 0x0100) | 0x0080 | kRcodeNoError);

    Bytes reply(kHeaderSize, 0);
    writeU16(reply, 0, parsed.id);
    writeU16(reply, 2, flags);
    writeU16(reply, 4, 1); // 1 Question
    writeU16(reply, 6, 1); // 1 Answer

    // Copy Question
    reply.insert(reply.end(),
                 query.begin() + static_cast<std::ptrdiff_t>(kHeaderSize),
                 query.begin() + static_cast<std::ptrdiff_t>(parsed.questionEnd));

    // Answer record pointing to Question name at offset 0x0C (12)
    reply.push_back(0xC0);
    reply.push_back(0x0C);

    // RR fixed fields are 10 bytes (type, class, ttl, rdlength) before the RDATA.
    const size_t rdLen = (parsed.type == kTypeA) ? 4 : 16;
    const size_t anStart = reply.size();
    reply.resize(anStart + 10 + rdLen, 0);

    writeU16(reply, anStart, parsed.type);
    writeU16(reply, anStart + 2, 1);      // class IN
    writeU32(reply, anStart + 4, 300);    // TTL 300s
    writeU16(reply, anStart + 8, static_cast<uint16_t>(rdLen));
    // Bytes remain 0 (0.0.0.0 or ::)
    return reply;
}

Bytes makeLocalIpResponse(const Bytes& query, const Query& parsed, const std::string& ip) {
    IN_ADDR v4{};
    IN6_ADDR v6{};
    if (inet_pton(AF_INET, ip.c_str(), &v4) == 1 && parsed.type == kTypeA) {
        const uint16_t queryFlags = readU16(query, 2);
        const uint16_t flags = static_cast<uint16_t>(0x8000 | (queryFlags & 0x0100) | 0x0080 | kRcodeNoError);

        Bytes reply(kHeaderSize, 0);
        writeU16(reply, 0, parsed.id);
        writeU16(reply, 2, flags);
        writeU16(reply, 4, 1);
        writeU16(reply, 6, 1);

        reply.insert(reply.end(),
                     query.begin() + static_cast<std::ptrdiff_t>(kHeaderSize),
                     query.begin() + static_cast<std::ptrdiff_t>(parsed.questionEnd));

        reply.push_back(0xC0);
        reply.push_back(0x0C);
        const size_t anStart = reply.size();
        reply.resize(anStart + 10 + 4);
        writeU16(reply, anStart, kTypeA);
        writeU16(reply, anStart + 2, 1);
        writeU32(reply, anStart + 4, 300);
        writeU16(reply, anStart + 8, 4);
        std::memcpy(reply.data() + anStart + 10, &v4, 4);
        return reply;
    }
    if (inet_pton(AF_INET6, ip.c_str(), &v6) == 1 && parsed.type == kTypeAaaa) {
        const uint16_t queryFlags = readU16(query, 2);
        const uint16_t flags = static_cast<uint16_t>(0x8000 | (queryFlags & 0x0100) | 0x0080 | kRcodeNoError);

        Bytes reply(kHeaderSize, 0);
        writeU16(reply, 0, parsed.id);
        writeU16(reply, 2, flags);
        writeU16(reply, 4, 1);
        writeU16(reply, 6, 1);

        reply.insert(reply.end(),
                     query.begin() + static_cast<std::ptrdiff_t>(kHeaderSize),
                     query.begin() + static_cast<std::ptrdiff_t>(parsed.questionEnd));

        reply.push_back(0xC0);
        reply.push_back(0x0C);
        const size_t anStart = reply.size();
        reply.resize(anStart + 10 + 16);
        writeU16(reply, anStart, kTypeAaaa);
        writeU16(reply, anStart + 2, 1);
        writeU32(reply, anStart + 4, 300);
        writeU16(reply, anStart + 8, 16);
        std::memcpy(reply.data() + anStart + 10, &v6, 16);
        return reply;
    }
    return makeErrorResponse(query, parsed, kRcodeNoError);
}

bool isResponseFor(const Bytes& packet, uint16_t id) {
    return packet.size() >= kHeaderSize && readU16(packet, 0) == id &&
           (readU16(packet, 2) & 0x8000) != 0;
}

bool isResponseFor(const Bytes& packet, const Bytes& query) {
    Query request;
    if (!parseQuery(query, request) || !isResponseFor(packet, request.id)) {
        return false;
    }
    ParsedMessage msg;
    if (!parseMessage(packet, msg) || msg.questions.size() != 1) {
        return false;
    }
    const Query& echo = msg.questions[0];
    return echo.name == request.name && echo.type == request.type &&
           echo.qclass == request.qclass;
}

bool responseCode(const Bytes& packet, uint8_t& rcode) {
    if (packet.size() < kHeaderSize) {
        return false;
    }
    rcode = static_cast<uint8_t>(readU16(packet, 2) & 0x0F);
    return true;
}

bool hasAdBit(const Bytes& packet) {
    return packet.size() >= kHeaderSize && (packet[3] & 0x20) != 0;
}

bool collectTtls(const Bytes& packet, std::vector<TtlField>& out) {
    out.clear();
    if (packet.size() < kHeaderSize) {
        return false;
    }
    const size_t questions = readU16(packet, 4);
    const size_t records = static_cast<size_t>(readU16(packet, 6)) + readU16(packet, 8) +
                           readU16(packet, 10);

    size_t off = kHeaderSize;
    for (size_t i = 0; i < questions; ++i) {
        if (!skipName(packet, off) || off + 4 > packet.size()) {
            return false;
        }
        off += 4;
    }
    for (size_t i = 0; i < records; ++i) {
        if (!skipName(packet, off) || off + 10 > packet.size()) {
            return false;
        }
        TtlField field;
        field.type = readU16(packet, off);
        field.offset = off + 4;
        field.ttl = readU32(packet, off + 4);
        const size_t rdlength = readU16(packet, off + 8);
        off += 10;
        if (off + rdlength > packet.size()) {
            return false;
        }
        off += rdlength;
        out.push_back(field);
    }
    return true;
}

void setId(Bytes& packet, uint16_t id) {
    if (packet.size() >= 2) {
        writeU16(packet, 0, id);
    }
}

void setTtl(Bytes& packet, size_t offset, uint32_t ttl) {
    if (offset + 4 > packet.size()) {
        return;
    }
    writeU32(packet, offset, ttl);
}

}  // namespace dns
