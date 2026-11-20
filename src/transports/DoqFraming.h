#pragma once

#include <utility>

#include "core/DnsMessage.h"

namespace doq {

// Write concludes the stream; read reports false on EOF or failure.
template <typename Write, typename Read>
bool exchangeFrame(const dns::Bytes& query, dns::Bytes& response, std::string& error,
                   Write write, Read read) {
    if (query.size() < dns::kHeaderSize || query.size() > 0xFFFF) {
        error = "invalid query size for DoQ";
        return false;
    }
    dns::Bytes framed = {static_cast<uint8_t>(query.size() >> 8), static_cast<uint8_t>(query.size())};
    framed.insert(framed.end(), query.begin(), query.end());
    framed[2] = 0;
    framed[3] = 0;
    size_t written = 0;
    // A concluded partial write cannot be retried on this stream.
    if (!write(framed.data(), framed.size(), written) || written != framed.size()) {
        error = "cannot send the complete DoQ query";
        return false;
    }
    const auto readExact = [&read](uint8_t* data, size_t length) {
        size_t offset = 0;
        while (offset < length) {
            size_t got = 0;
            if (!read(data + offset, length - offset, got) || got == 0) {
                return false;
            }
            offset += got;
        }
        return true;
    };
    uint8_t prefix[2] = {};
    if (!readExact(prefix, sizeof(prefix))) {
        error = "DoQ reply prefix is incomplete";
        return false;
    }
    const size_t length = (static_cast<size_t>(prefix[0]) << 8) | prefix[1];
    if (length < dns::kHeaderSize) {
        error = "DoQ reply length is out of range";
        return false;
    }
    dns::Bytes reply(length);
    if (!readExact(reply.data(), reply.size())) {
        error = "DoQ reply is incomplete";
        return false;
    }
    if (!dns::isResponseFor(reply, 0)) {
        error = "DoQ reply does not match the query";
        return false;
    }
    dns::setId(reply, static_cast<uint16_t>((static_cast<uint16_t>(query[0]) << 8) | query[1]));
    response = std::move(reply);
    error.clear();
    return true;
}

} // namespace doq
