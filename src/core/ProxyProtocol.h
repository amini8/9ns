#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace proxyproto {

using Bytes = std::vector<uint8_t>;
inline constexpr size_t kMaxHandshakeSize = 8192;
inline constexpr size_t kMaxDomainLength = 253;
inline constexpr size_t kMaxAuthLength = 255;

enum class Protocol { Unknown, Socks5, Socks4, HttpConnect };
enum class Stage { NeedMore, Done, Malformed };

struct Target {
    std::string host;
    uint16_t port = 0;
    bool hostIsNumeric = false;
};

Protocol detectProtocol(uint8_t firstByte);
Protocol detectProtocol(const Bytes& bytes);

// Parsers leave outputs unchanged and reset consumed to zero unless Done.
// Consumed excludes pipelined application bytes. No parser performs I/O.
struct Socks5Greeting { Bytes methods; };
Stage parseSocks5Greeting(const Bytes& bytes, Socks5Greeting& out, size_t& consumed);
Bytes makeSocks5Greeting(const Bytes& methods = {0});
Bytes makeSocks5MethodChoice(uint8_t method);
Stage parseSocks5MethodChoice(const Bytes& bytes, uint8_t& method, size_t& consumed);

struct Socks5Auth { std::string username; std::string password; };
Stage parseSocks5Auth(const Bytes& bytes, Socks5Auth& out, size_t& consumed);
Bytes makeSocks5Auth(const Socks5Auth& auth);
Bytes makeSocks5AuthReply(uint8_t status);
Stage parseSocks5AuthReply(const Bytes& bytes, uint8_t& status, size_t& consumed);

enum class Socks5Command : uint8_t { Connect = 1, Bind = 2, UdpAssociate = 3 };
struct Socks5Request {
    Socks5Command command = Socks5Command::Connect;
    Target target;
};
struct Socks5Reply { uint8_t code = 0; Target target; };
// Unknown commands are retained so the caller can send UnsupportedCommand.
Stage parseSocks5Request(const Bytes& bytes, Socks5Request& out, size_t& consumed);
Bytes makeSocks5Request(const Socks5Request& request);
Bytes makeSocks5Reply(uint8_t code);
Stage parseSocks5Reply(const Bytes& bytes, Socks5Reply& out, size_t& consumed);

struct Socks4Request {
    uint8_t command = 1;
    Target target;
    std::string userId;
};
struct Socks4Reply { uint8_t code = 0; Target target; };
Stage parseSocks4Request(const Bytes& bytes, Socks4Request& out, size_t& consumed);
Bytes makeSocks4Request(const Socks4Request& request);
Bytes makeSocks4Reply(uint8_t code);
Stage parseSocks4Reply(const Bytes& bytes, Socks4Reply& out, size_t& consumed);

struct HttpConnectRequest {
    Target target;
    bool hasCredentials = false;
    std::string username;
    std::string password;
    std::string method;
    bool isConnect = false;
};
struct HttpResponse { int statusCode = 0; };
Stage parseHttpConnect(const Bytes& bytes, HttpConnectRequest& out, size_t& consumed);
Bytes makeHttpConnectRequest(const HttpConnectRequest& request);
// Responses contain no body; 407 includes a Basic proxy-auth challenge.
Bytes makeHttpResponse(int statusCode);
Stage parseHttpResponse(const Bytes& bytes, HttpResponse& out, size_t& consumed);
bool decodeBase64(const std::string& encoded, std::string& decoded);

// Builders reject invalid fields with std::invalid_argument.
enum class Refusal { Blocked, NotFound, Failed, Authentication, UnsupportedCommand, UnsupportedAddress };
struct RefusalCodes { uint8_t socks5; uint8_t socks4; int http; };
RefusalCodes refusalFor(Refusal refusal);

} // namespace proxyproto
