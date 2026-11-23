#pragma once

#include <string>

#include "core/Net.h"
#include "core/Config.h"

void parseTunnelEndpoint(const std::string& address, uint16_t defaultPort,
                         std::string& host, uint16_t& port);

// Winsock must be initialized. An enabled proxy never falls back to a direct connection.
Socket openProxyTunnel(const UpstreamProxyConfig& proxy, const std::string& host,
                       uint16_t port, std::string& error);

// "host:port" for WinHTTP's WINHTTP_ACCESS_TYPE_NAMED_PROXY argument, or false when the
// proxy is disabled. WinHTTP has no SOCKS support, so an enabled non-HTTP proxy returns
// false with error set: the caller must fail rather than fall back to a direct connection.
bool winHttpProxyName(const UpstreamProxyConfig& proxy, uint16_t defaultPort, std::wstring& out,
                      std::string& error);

// Applies the configured proxy credentials (Basic) to an opened WinHTTP request.
void applyWinHttpCredentials(void* request, const UpstreamProxyConfig& proxy);
