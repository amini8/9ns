#pragma once

#include <string>

#include "core/DnsMessage.h"

// DNSSEC status under upstream-validation semantics.
enum class DnsSecStatus {
    Secure,         // the AD bit was reported over an authenticated upstream channel
    Insecure,       // the upstream reported the name as not DNSSEC-protected
    Bogus,          // failure signal: upstream SERVFAIL or a signature outside its validity window
    Indeterminate   // cannot be established: unauthenticated channel or unverified evidence
};

std::string dnsSecStatusToString(DnsSecStatus status);

// Upstream DNSSEC validation assessor. No signature, RRset or chain verification
// is performed locally. Secure requires an authenticated upstream channel (verified
// TLS/DoT/DoQ with tls_verify enabled, or DNSCrypt) that reported the AD bit; the
// mere presence of an RRSIG is never proof and never yields Secure.
class DnsSec {
public:
    DnsSec();
    ~DnsSec();

    // Determines the DNSSEC status of a response packet. `authenticatedUpstream`
    // must be true only when the answer arrived over an authenticated channel.
    // Returns Bogus for SERVFAIL and for signatures outside their validity window.
    DnsSecStatus validate(const dns::Bytes& response, bool authenticatedUpstream) const;
};
