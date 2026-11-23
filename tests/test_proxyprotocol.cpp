#include <QtTest/QtTest>

#include <algorithm>
#include <stdexcept>

#include "core/ProxyProtocol.h"

using namespace proxyproto;

namespace {
Bytes bytes(const std::string& text) { return Bytes(text.begin(), text.end()); }
std::string string(const Bytes& data) { return std::string(data.begin(), data.end()); }
std::string longDomain(size_t length) {
    std::string result;
    while (length > 63) {
        result += std::string(63, 'a') + '.';
        length -= 64;
    }
    return result + std::string(length, 'b');
}
template<class Output, class Parser>
void fragmented(const Bytes& frame, Parser parser) {
    for (size_t cut = 0; cut < frame.size(); ++cut) {
        Output out{};
        size_t consumed = 999;
        QCOMPARE(parser(Bytes(frame.begin(), frame.begin() + cut), out, consumed), Stage::NeedMore);
        QCOMPARE(consumed, size_t(0));
    }
    Output out{};
    size_t consumed = 999;
    QCOMPARE(parser(frame, out, consumed), Stage::Done);
    QCOMPARE(consumed, frame.size());
    Bytes pipeline = frame;
    pipeline.insert(pipeline.end(), kMaxHandshakeSize + 1, 0xFF);
    QCOMPARE(parser(pipeline, out, consumed), Stage::Done);
    QCOMPARE(consumed, frame.size());
}
template<class Output, class Parser>
void malformed(const Bytes& frame, Parser parser) {
    Output out{};
    size_t consumed = 999;
    QCOMPARE(parser(frame, out, consumed), Stage::Malformed);
    QCOMPARE(consumed, size_t(0));
}
Bytes http(const std::string& authority, const std::string& headers = {}) {
    return bytes("CONNECT " + authority + " HTTP/1.1\r\n" + headers + "\r\n");
}
}

class TestProxyProtocol : public QObject {
    Q_OBJECT

private slots:
    void detection() {
        QCOMPARE(detectProtocol(Bytes{}), Protocol::Unknown);
        QCOMPARE(detectProtocol(5), Protocol::Socks5);
        QCOMPARE(detectProtocol(4), Protocol::Socks4);
        QCOMPARE(detectProtocol('C'), Protocol::HttpConnect);
        QCOMPARE(detectProtocol('c'), Protocol::HttpConnect);
        QCOMPARE(detectProtocol('G'), Protocol::HttpConnect);
        for (uint8_t value : {uint8_t(0), uint8_t(1), uint8_t(32), uint8_t(127), uint8_t(255)})
            QCOMPARE(detectProtocol(value), Protocol::Unknown);
    }
    void greetingsAndChoices() {
        for (const Bytes& methods : {Bytes{0}, Bytes{0, 2}, Bytes{1, 0x80, 0xFF}, Bytes(255, 2)}) {
            const Bytes frame = makeSocks5Greeting(methods);
            fragmented<Socks5Greeting>(frame, parseSocks5Greeting);
            Socks5Greeting parsed;
            size_t consumed = 0;
            QCOMPARE(parseSocks5Greeting(frame, parsed, consumed), Stage::Done);
            QCOMPARE(parsed.methods, methods);
        }
        malformed<Socks5Greeting>({4}, parseSocks5Greeting);
        malformed<Socks5Greeting>({5, 0}, parseSocks5Greeting);
        QVERIFY_EXCEPTION_THROWN(makeSocks5Greeting({}), std::invalid_argument);
        QVERIFY_EXCEPTION_THROWN(makeSocks5Greeting(Bytes(256, 0)), std::invalid_argument);
        for (uint8_t method : {uint8_t(0), uint8_t(2), uint8_t(0x80), uint8_t(0xFF)}) {
            const Bytes frame = makeSocks5MethodChoice(method);
            QCOMPARE(frame, (Bytes{5, method}));
            fragmented<uint8_t>(frame, parseSocks5MethodChoice);
            uint8_t out = 0;
            size_t consumed = 0;
            QCOMPARE(parseSocks5MethodChoice(frame, out, consumed), Stage::Done);
            QCOMPARE(out, method);
        }
        malformed<uint8_t>({4, 0}, parseSocks5MethodChoice);
    }
    void socksAuthentication() {
        for (const Socks5Auth& auth : {Socks5Auth{"user", "secret"}, Socks5Auth{std::string(255, 'u'), std::string(255, 'p')}}) {
            const Bytes frame = makeSocks5Auth(auth);
            fragmented<Socks5Auth>(frame, parseSocks5Auth);
            Socks5Auth out;
            size_t consumed = 0;
            QCOMPARE(parseSocks5Auth(frame, out, consumed), Stage::Done);
            QCOMPARE(out.username, auth.username);
            QCOMPARE(out.password, auth.password);
        }
        for (const Bytes& bad : {Bytes{2}, Bytes{1, 0}, Bytes{1, 1, 'u', 0},
                                Bytes{1, 1, 0, 1, 'p'}, Bytes{1, 1, 'u', 1, '\n'}, Bytes{1, 1, 127, 1, 'p'}})
            malformed<Socks5Auth>(bad, parseSocks5Auth);
        for (const Socks5Auth& bad : {Socks5Auth{"", "p"}, Socks5Auth{"u", ""},
                                     Socks5Auth{std::string(256, 'u'), "p"}, Socks5Auth{"u", std::string(256, 'p')},
                                     Socks5Auth{"a\rb", "p"}})
            QVERIFY_EXCEPTION_THROWN(makeSocks5Auth(bad), std::invalid_argument);
        for (uint8_t status : {uint8_t(0), uint8_t(1), uint8_t(255)}) {
            QCOMPARE(makeSocks5AuthReply(status), (Bytes{1, status}));
            fragmented<uint8_t>(makeSocks5AuthReply(status), parseSocks5AuthReply);
        }
        malformed<uint8_t>({5, 0}, parseSocks5AuthReply);
    }
    void socks5TargetsAndCommands() {
        const std::vector<Target> targets = {
            {"192.0.2.9", 443, true}, {"0.0.0.0", 1, true}, {"255.255.255.255", 65535, true},
            {"::", 443, true}, {"::1", 443, true}, {"2001:db8::1", 443, true},
            {"2001:db8:0:1:2:3:4:5", 443, true}, {"::ffff:192.0.2.1", 443, true},
            {"example.com", 80, false}, {"example.com.", 80, false}, {longDomain(253), 65535, false}
        };
        for (const Target& target : targets) {
            for (uint8_t command : {uint8_t(1), uint8_t(2), uint8_t(3), uint8_t(99)}) {
                const Socks5Request request{static_cast<Socks5Command>(command), target};
                const Bytes frame = makeSocks5Request(request);
                fragmented<Socks5Request>(frame, parseSocks5Request);
                Socks5Request out;
                size_t consumed = 0;
                QCOMPARE(parseSocks5Request(frame, out, consumed), Stage::Done);
                QCOMPARE(out.command, request.command);
                QCOMPARE(out.target.port, target.port);
                QCOMPARE(out.target.hostIsNumeric, target.hostIsNumeric);
                QCOMPARE(makeSocks5Request(out), frame);
                if (target.host.find(':') == std::string::npos) QCOMPARE(out.target.host, target.host);
            }
        }
        const Bytes v4 = makeSocks5Request({Socks5Command::Connect, {"192.0.2.9", 443, true}});
        QCOMPARE(v4, (Bytes{5, 1, 0, 1, 192, 0, 2, 9, 1, 187}));
        const Bytes named = makeSocks5Request({Socks5Command::Connect, {"a", 80, false}});
        QCOMPARE(named, (Bytes{5, 1, 0, 3, 1, 'a', 0, 80}));
        fragmented<Socks5Request>(makeSocks5Request({Socks5Command::UdpAssociate, {"0.0.0.0", 0, true}}), parseSocks5Request);
    }
    void socks5RejectsMalformedFrames() {
        for (const Bytes& bad : {Bytes{4}, Bytes{5, 1, 1}, Bytes{5, 1, 0, 0}, Bytes{5, 1, 0, 2},
                                Bytes{5, 1, 0, 3, 0}, Bytes{5, 1, 0, 3, 254}, Bytes{5, 1, 0, 3, 255},
                                Bytes{5, 1, 0, 1, 1, 2, 3, 4, 0, 0}, Bytes{5, 1, 0, 3, 1, 0, 0, 80}})
            malformed<Socks5Request>(bad, parseSocks5Request);
        for (const std::string& host : {std::string("a/b"), std::string("a@b"), std::string("a b"),
                                      std::string("a\nb"), std::string("a\0b", 3), std::string("-a"),
                                      std::string("a-"), std::string("a..b"), std::string("a.."),
                                      std::string("."), std::string(64, 'a'), longDomain(254),
                                      std::string("999.1.1.1"), std::string("01.2.3.4")}) {
            Bytes frame = {5, 1, 0, 3, static_cast<uint8_t>(host.size())};
            frame.insert(frame.end(), host.begin(), host.end());
            frame.insert(frame.end(), {0, 80});
            malformed<Socks5Request>(frame, parseSocks5Request);
            QVERIFY_EXCEPTION_THROWN(makeSocks5Request({Socks5Command::Connect, {host, 80, false}}), std::invalid_argument);
        }
        QVERIFY_EXCEPTION_THROWN(makeSocks5Request({Socks5Command::Connect, {"a", 0, false}}), std::invalid_argument);
        QVERIFY_EXCEPTION_THROWN(makeSocks5Request({Socks5Command::Connect, {"a", 80, true}}), std::invalid_argument);
    }
    void ipv6ValidationAndCanonicalization() {
        const std::vector<std::pair<std::string, std::string>> cases = {
            {"0:0:0:0:0:0:0:0", "::"}, {"0:0:0:0:0:0:0:1", "::1"},
            {"2001:0DB8:0:0:1:0:0:1", "2001:db8::1:0:0:1"},
            {"1:2:3:4:5:6:0:0", "1:2:3:4:5:6::"},
            {"1:2:3:4:5:0:7:8", "1:2:3:4:5:0:7:8"},
            {"::ffff:192.0.2.1", "::ffff:c000:201"}
        };
        for (const auto& item : cases) {
            Socks5Request out;
            size_t consumed = 0;
            QCOMPARE(parseSocks5Request(makeSocks5Request({Socks5Command::Connect, {item.first, 80, true}}), out, consumed), Stage::Done);
            QCOMPARE(out.target.host, item.second);
        }
        for (const std::string& host : {":::1", "1:::2", "1::2::3", "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9",
                                       "1:2:3:4:5:6:7:8::", "12345::1", "gg::1", "fe80::1%2", "::1:",
                                       ":1:2:3:4:5:6:7", "192.0.2.1::", "::ffff:192.0.2.999", "::ffff:01.2.3.4"}) {
            QVERIFY_EXCEPTION_THROWN(makeSocks5Request({Socks5Command::Connect, {host, 80, true}}), std::invalid_argument);
            malformed<HttpConnectRequest>(http("[" + host + "]:80"), parseHttpConnect);
        }
    }
    void socks5Replies() {
        for (uint8_t code = 0; code <= 8; ++code) {
            const Bytes frame = makeSocks5Reply(code);
            QCOMPARE(frame, (Bytes{5, code, 0, 1, 0, 0, 0, 0, 0, 0}));
            fragmented<Socks5Reply>(frame, parseSocks5Reply);
            Socks5Reply out;
            size_t consumed = 0;
            QCOMPARE(parseSocks5Reply(frame, out, consumed), Stage::Done);
            QCOMPARE(out.code, code);
            QCOMPARE(out.target.host, std::string("0.0.0.0"));
            QCOMPARE(out.target.port, uint16_t(0));
        }
        for (const Target& target : {Target{"example.com", 1234, false}, Target{"::1", 1234, true}}) {
            Bytes frame = makeSocks5Request({Socks5Command::Connect, target});
            frame[1] = 0;
            fragmented<Socks5Reply>(frame, parseSocks5Reply);
        }
        for (const Bytes& bad : {Bytes{4}, Bytes{5, 9}, Bytes{5, 0, 1}, Bytes{5, 0, 0, 9}})
            malformed<Socks5Reply>(bad, parseSocks5Reply);
        QVERIFY_EXCEPTION_THROWN(makeSocks5Reply(9), std::invalid_argument);
    }
    void socks4And4a() {
        for (const Target& target : {Target{"192.0.2.1", 80, true}, Target{"0.0.0.0", 80, true},
                                    Target{"example.com", 443, false}, Target{longDomain(253), 65535, false}}) {
            for (const std::string& user : {std::string(), std::string("user"), std::string(255, 'u')}) {
                for (uint8_t command : {uint8_t(1), uint8_t(2), uint8_t(99)}) {
                    const Socks4Request request{command, target, user};
                    const Bytes frame = makeSocks4Request(request);
                    fragmented<Socks4Request>(frame, parseSocks4Request);
                    Socks4Request out;
                    size_t consumed = 0;
                    QCOMPARE(parseSocks4Request(frame, out, consumed), Stage::Done);
                    QCOMPARE(out.target.host, target.host);
                    QCOMPARE(out.target.port, target.port);
                    QCOMPARE(out.target.hostIsNumeric, target.hostIsNumeric);
                    QCOMPARE(out.command, command);
                    QCOMPARE(out.userId, user);
                    QCOMPARE(makeSocks4Request(out), frame);
                }
            }
        }
        QCOMPARE(makeSocks4Request({1, {"a", 80, false}, "u"}), (Bytes{4, 1, 0, 80, 0, 0, 0, 1, 'u', 0, 'a', 0}));
        for (uint8_t marker : {uint8_t(1), uint8_t(255)}) {
            const Bytes frame{4, 1, 0, 80, 0, 0, 0, marker, 0, 'a', 0};
            fragmented<Socks4Request>(frame, parseSocks4Request);
        }
        for (const Bytes& bad : {Bytes{5}, Bytes{4, 1, 0, 0, 1, 2, 3, 4},
                                Bytes{4, 1, 0, 80, 1, 2, 3, 4, '\n', 0},
                                Bytes{4, 1, 0, 80, 0, 0, 0, 1, 0, 0},
                                Bytes{4, 1, 0, 80, 0, 0, 0, 1, 0, 'a', '/', 'b', 0}})
            malformed<Socks4Request>(bad, parseSocks4Request);
        Bytes longUser{4, 1, 0, 80, 1, 2, 3, 4};
        longUser.insert(longUser.end(), 256, 'u');
        malformed<Socks4Request>(longUser, parseSocks4Request);
        Bytes longHost{4, 1, 0, 80, 0, 0, 0, 1, 0};
        longHost.insert(longHost.end(), 254, 'a');
        malformed<Socks4Request>(longHost, parseSocks4Request);
        QVERIFY_EXCEPTION_THROWN(makeSocks4Request({1, {"::1", 80, true}, ""}), std::invalid_argument);
        QVERIFY_EXCEPTION_THROWN(makeSocks4Request({1, {"0.0.0.1", 80, true}, ""}), std::invalid_argument);
        QVERIFY_EXCEPTION_THROWN(makeSocks4Request({1, {"a", 80, false}, std::string(256, 'u')}), std::invalid_argument);
        for (uint8_t code = 0x5A; code <= 0x5D; ++code) {
            QCOMPARE(makeSocks4Reply(code), (Bytes{0, code, 0, 0, 0, 0, 0, 0}));
            fragmented<Socks4Reply>(makeSocks4Reply(code), parseSocks4Reply);
        }
        malformed<Socks4Reply>({4, 0x5A}, parseSocks4Reply);
        malformed<Socks4Reply>({0, 0x59}, parseSocks4Reply);
        malformed<Socks4Reply>({0, 0x5E}, parseSocks4Reply);
        QVERIFY_EXCEPTION_THROWN(makeSocks4Reply(0), std::invalid_argument);
    }
    void httpTargetsMethodsAndFraming() {
        for (const Target& target : {Target{"example.com", 443, false}, Target{longDomain(253), 65535, false},
                                    Target{"192.0.2.1", 1, true}, Target{"::1", 443, true},
                                    Target{"::ffff:192.0.2.1", 443, true}}) {
            HttpConnectRequest request;
            request.target = target;
            const Bytes frame = makeHttpConnectRequest(request);
            fragmented<HttpConnectRequest>(frame, parseHttpConnect);
            HttpConnectRequest out;
            size_t consumed = 0;
            QCOMPARE(parseHttpConnect(frame, out, consumed), Stage::Done);
            QVERIFY(out.isConnect);
            QVERIFY(!out.hasCredentials);
            QCOMPARE(out.method, std::string("CONNECT"));
            QCOMPARE(out.target.host, target.host);
            QCOMPARE(out.target.port, target.port);
            QCOMPARE(out.target.hostIsNumeric, target.hostIsNumeric);
        }
        for (const std::string& method : {"CONNECT", "connect", "CoNnEcT", "GET", "POST"}) {
            const bool connect = method != "GET" && method != "POST";
            const Bytes frame = bytes(method + (connect ? " example.com:443" : " /resource") + " HTTP/1.0\r\nx-TesT: yes\r\n\r\n");
            fragmented<HttpConnectRequest>(frame, parseHttpConnect);
            HttpConnectRequest out;
            size_t consumed = 0;
            QCOMPARE(parseHttpConnect(frame, out, consumed), Stage::Done);
            QCOMPARE(out.method, method);
            QCOMPARE(out.isConnect, connect);
        }
        fragmented<HttpConnectRequest>(http("a:80", "Content-Length: 0\r\n"), parseHttpConnect);
    }
    void httpRejectsInvalidTargetsAndHeaders() {
        for (const std::string& target : {"a", "a:", "a:0", "a:65536", "a:100000", "a:-1", "a:+1", "a:8x",
                                         "a:80:90", "a: 80", "user@a:80", "http://a:80", "a/b:80", ":80", "a..:80",
                                         "999.1.1.1:80", "01.2.3.4:80", "::1:80", "[::1]", "[::1]:0", "[::1]x:80",
                                         "[127.0.0.1]:80", "[::1:80", "[::1]:80x", "[]:80"})
            malformed<HttpConnectRequest>(http(target), parseHttpConnect);
        for (const std::string& frame : {"CONNECT a:80 HTTP/2.0\r\n\r\n", "CONNECT  a:80 HTTP/1.1\r\n\r\n",
                                        "CONNECT a:80 HTTP/1.1 extra\r\n\r\n", "CONNECT\ta:80 HTTP/1.1\r\n\r\n",
                                        "CONNECT a:80 HTTP/1.1\n\n", "CONNECT a:80 HTTP/1.1\rX", "\r\n\r\n"})
            malformed<HttpConnectRequest>(bytes(frame), parseHttpConnect);
        for (const std::string& headers : {"Invalid\r\n", "Bad Name: x\r\n", " Header: x\r\n", "Header : x\r\n",
                                          "Header: x\r\n folded\r\n", "Header: x\x01\r\n", "Header: x\x7f\r\n",
                                          "Content-Length: 1\r\n", "Content-Length: 0\r\nContent-Length: 0\r\n",
                                          "Transfer-Encoding: chunked\r\n"})
            malformed<HttpConnectRequest>(http("a:80", headers), parseHttpConnect);
        malformed<HttpConnectRequest>(http("a:80", std::string("X: a\0b\r\n", 8)), parseHttpConnect);
        malformed<HttpConnectRequest>(http(longDomain(254) + ":80"), parseHttpConnect);
    }
    void httpHeaderLimit() {
        const Bytes base = http("a:80", "X: \r\n");
        const size_t padding = kMaxHandshakeSize - base.size();
        const Bytes maximum = http("a:80", "X: " + std::string(padding, 'a') + "\r\n");
        QCOMPARE(maximum.size(), kMaxHandshakeSize);
        fragmented<HttpConnectRequest>(maximum, parseHttpConnect);
        malformed<HttpConnectRequest>(http("a:80", "X: " + std::string(padding + 1, 'a') + "\r\n"), parseHttpConnect);
        malformed<HttpConnectRequest>(Bytes(kMaxHandshakeSize, 'a'), parseHttpConnect);
        HttpConnectRequest out;
        size_t consumed = 9;
        QCOMPARE(parseHttpConnect(Bytes(kMaxHandshakeSize - 1, 'a'), out, consumed), Stage::NeedMore);
        QCOMPARE(consumed, size_t(0));
    }
    void base64Vectors() {
        const std::vector<std::pair<std::string, std::string>> vectors = {
            {"", ""}, {"Zg==", "f"}, {"Zm8=", "fo"}, {"Zm9v", "foo"},
            {"Zm9vYg==", "foob"}, {"Zm9vYmE=", "fooba"}, {"Zm9vYmFy", "foobar"},
            {"dXNlcjpwYXNz", "user:pass"}, {"AAEC/w==", std::string("\0\1\2\xff", 4)}
        };
        for (const auto& item : vectors) {
            std::string decoded = "unchanged";
            QVERIFY(decodeBase64(item.first, decoded));
            QCOMPARE(decoded, item.second);
        }
        for (const std::string& encoded : {"Zg", "Zg=", "Zg===", "Zg==\n", " Zg==", "Z g=", "=m9v", "Z=9v", "Zm=v",
                                          "====", "Zg==AAAA", "Zh==", "Zm9=", "Zm-v", "Zm_v", "Zm9v\t", "Zm9v\r\n"}) {
            std::string decoded = "unchanged";
            QVERIFY(!decodeBase64(encoded, decoded));
            QCOMPARE(decoded, std::string("unchanged"));
        }
    }
    void httpBasicAuthentication() {
        for (const std::pair<std::string, std::string>& auth : {
                 std::make_pair(std::string("user"), std::string("p:a:ss")),
                 std::make_pair(std::string("user"), std::string()),
                 std::make_pair(std::string(255, 'u'), std::string(255, 'p'))}) {
            HttpConnectRequest request;
            request.target = {"example.com", 443, false};
            request.hasCredentials = true;
            request.username = auth.first;
            request.password = auth.second;
            const Bytes frame = makeHttpConnectRequest(request);
            fragmented<HttpConnectRequest>(frame, parseHttpConnect);
            HttpConnectRequest out;
            size_t consumed = 0;
            QCOMPARE(parseHttpConnect(frame, out, consumed), Stage::Done);
            QVERIFY(out.hasCredentials);
            QCOMPARE(out.username, auth.first);
            QCOMPARE(out.password, auth.second);
        }
        HttpConnectRequest out;
        size_t consumed = 0;
        QCOMPARE(parseHttpConnect(http("a:80", "pRoXy-AuThOrIzAtIoN:\t bAsIc\t dTpw \t\r\n"), out, consumed), Stage::Done);
        QVERIFY(out.hasCredentials);
        QCOMPARE(out.username, std::string("u"));
        QCOMPARE(out.password, std::string("p"));
        QCOMPARE(parseHttpConnect(http("a:80", "Proxy-Authorization: Bearer abc\r\n"), out, consumed), Stage::Done);
        QVERIFY(!out.hasCredentials);
        for (const std::string& encoded : {"", "dTpw=", "dTpw!!!!", "dTpw dTpw", "dXNlcg==", "OnA=", "dToA", "dToK", "dTof", "dTp/", "dQA6cA=="})
            malformed<HttpConnectRequest>(http("a:80", "Proxy-Authorization: Basic " + encoded + "\r\n"), parseHttpConnect);
        malformed<HttpConnectRequest>(http("a:80", "Proxy-Authorization: Basic\r\n"), parseHttpConnect);
        malformed<HttpConnectRequest>(http("a:80", "Proxy-Authorization: Basic dTpw\r\nproxy-authorization: Basic dTpw\r\n"), parseHttpConnect);
        HttpConnectRequest request;
        request.target = {"a", 80, false};
        request.hasCredentials = true;
        request.password = "p";
        for (const std::string& name : {std::string(), std::string(256, 'u'), std::string("u:s"), std::string("u\ns")}) {
            request.username = name;
            QVERIFY_EXCEPTION_THROWN(makeHttpConnectRequest(request), std::invalid_argument);
        }
        request.username = "u";
        request.password = std::string(256, 'p');
        QVERIFY_EXCEPTION_THROWN(makeHttpConnectRequest(request), std::invalid_argument);
    }
    void httpResponsesAndRefusals() {
        for (int code : {200, 400, 403, 405, 407, 500, 502, 503, 504}) {
            const Bytes frame = makeHttpResponse(code);
            fragmented<HttpResponse>(frame, parseHttpResponse);
            HttpResponse out;
            size_t consumed = 0;
            QCOMPARE(parseHttpResponse(frame, out, consumed), Stage::Done);
            QCOMPARE(out.statusCode, code);
        }
        QCOMPARE(string(makeHttpResponse(200)), std::string("HTTP/1.1 200 Connection Established\r\n\r\n"));
        QVERIFY(string(makeHttpResponse(407)).find("Proxy-Authenticate: Basic realm=\"9NS\"\r\n") != std::string::npos);
        QVERIFY(string(makeHttpResponse(405)).find("Allow: CONNECT\r\n") != std::string::npos);
        fragmented<HttpResponse>(bytes("HTTP/1.0 204 \r\nX: y\r\n\r\n"), parseHttpResponse);
        for (const std::string& frame : {"HTTP/2.0 200 OK\r\n\r\n", "HTTP/1.1 20 OK\r\n\r\n", "HTTP/1.1 2000 OK\r\n\r\n",
                                        "HTTP/1.1 099 OK\r\n\r\n", "HTTP/1.1 600 OK\r\n\r\n", "HTTP/1.1 2a0 OK\r\n\r\n",
                                        "HTTP/1.1 200\r\n\r\n", "HTTP/1.1 200 OK\r\nBad\r\n\r\n"})
            malformed<HttpResponse>(bytes(frame), parseHttpResponse);
        malformed<HttpResponse>(Bytes(kMaxHandshakeSize, 'x'), parseHttpResponse);
        QVERIFY_EXCEPTION_THROWN(makeHttpResponse(999), std::invalid_argument);
        const std::vector<std::pair<Refusal, RefusalCodes>> mappings = {
            {Refusal::Blocked, {2, 0x5B, 403}}, {Refusal::NotFound, {4, 0x5B, 502}},
            {Refusal::Failed, {1, 0x5B, 502}}, {Refusal::Authentication, {2, 0x5B, 407}},
            {Refusal::UnsupportedCommand, {7, 0x5B, 405}}, {Refusal::UnsupportedAddress, {8, 0x5B, 400}}
        };
        for (const auto& mapping : mappings) {
            const auto result = refusalFor(mapping.first);
            QCOMPARE(result.socks5, mapping.second.socks5);
            QCOMPARE(result.socks4, mapping.second.socks4);
            QCOMPARE(result.http, mapping.second.http);
        }
    }
    void unsuccessfulParsesPreserveOutputs() {
        size_t consumed = 999;
        Socks5Greeting greeting{{9}};
        QCOMPARE(parseSocks5Greeting({5, 2, 0}, greeting, consumed), Stage::NeedMore);
        QCOMPARE(greeting.methods, Bytes{9});
        Socks5Auth auth{"saved", "secret"};
        QCOMPARE(parseSocks5Auth({1, 1, 0, 1, 'p'}, auth, consumed), Stage::Malformed);
        QCOMPARE(auth.username, std::string("saved"));
        Socks5Request socks5{Socks5Command::Bind, {"saved", 9, false}};
        QCOMPARE(parseSocks5Request({5, 1, 0, 1, 1, 2, 3, 4, 0, 0}, socks5, consumed), Stage::Malformed);
        QCOMPARE(socks5.target.host, std::string("saved"));
        QCOMPARE(socks5.command, Socks5Command::Bind);
        Socks4Request socks4{2, {"saved", 9, false}, "user"};
        QCOMPARE(parseSocks4Request({4, 1, 0, 80, 0, 0, 0, 1, 0}, socks4, consumed), Stage::NeedMore);
        QCOMPARE(socks4.userId, std::string("user"));
        QCOMPARE(socks4.target.host, std::string("saved"));
        HttpConnectRequest connect;
        connect.username = "saved";
        QCOMPARE(parseHttpConnect(http("a:0"), connect, consumed), Stage::Malformed);
        QCOMPARE(connect.username, std::string("saved"));
        HttpResponse response{201};
        QCOMPARE(parseHttpResponse(bytes("HTTP/1.1 999 NO\r\n\r\n"), response, consumed), Stage::Malformed);
        QCOMPARE(response.statusCode, 201);
        QCOMPARE(consumed, size_t(0));
    }
};

QTEST_GUILESS_MAIN(TestProxyProtocol)
#include "test_proxyprotocol.moc"
