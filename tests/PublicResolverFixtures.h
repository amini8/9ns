#pragma once

#include <QByteArray>

#include "core/Config.h"
#include "web/PublicResolversLoader.h"

namespace publicResolverFixtures {

inline PublicDnsItem item(unsigned char protocol, const std::string& name = "resolver",
                          const QByteArray& host = "resolver.example") {
    QByteArray bytes;
    bytes.append(static_cast<char>(protocol));
    auto field = [&](const QByteArray& value) {
        bytes.append(static_cast<char>(value.size()));
        bytes.append(value);
    };
    if (protocol == 0x81) {
        field("192.0.2.1:443");
    } else {
        bytes.append(QByteArray(8, '\0'));
        if (protocol == 0x01) {
            field("192.0.2.1:443");
            field(QByteArray(32, 'k'));
            field(host);
        } else if (protocol == 0x02 || protocol == 0x04) {
            field("");
            bytes.append('\0');
            field(host);
            if (protocol == 0x02) field("/dns-query");
            else { bytes.append('\x03'); bytes.append('\x55'); }
        } else {
            field(host);
            field("/dns-query");
        }
    }
    PublicDnsItem result;
    result.name = name;
    result.stamp = "sdns://" + bytes.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals).toStdString();
    result.protocol = "intentionally wrong";
    return result;
}

inline std::string markdown(const PublicDnsItem& entry) {
    return "## " + entry.name + "\nNo logs, DNSSEC, non-filtering\n" + entry.stamp + "\n";
}

inline Config config() {
    Config result;
    UpstreamConfig upstream;
    upstream.name = "existing";
    upstream.type = "plain";
    upstream.address = "192.0.2.53";
    result.upstreams.push_back(upstream);
    result.defaultTarget = upstream.name;
    return result;
}

}  // namespace publicResolverFixtures
