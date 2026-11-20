#include "core/Pool.h"

#include <algorithm>
#include <cstdlib>
#include <random>
#include <stdexcept>
#include <utility>

Pool::Pool(std::string name, std::string strategy, std::vector<Upstream*> upstreams)
    : name_(std::move(name)), strategy_(std::move(strategy)), upstreams_(std::move(upstreams)) {
    if (upstreams_.empty()) {
        throw std::runtime_error("pool '" + name_ + "' must have at least one server");
    }
    for (auto* u : upstreams_) {
        latencies_[u->name()] = 100; // initial default estimate
    }
}

Pool::~Pool() = default;

std::string Pool::allServersFailedError(const std::string& lastError) const {
    return "all servers in pool '" + name_ + "' failed: " + lastError;
}

bool Pool::exchange(const dns::Bytes& query, dns::Bytes& response, std::string& error, std::string& usedUpstream) {
    if (strategy_ == "round_robin") {
        return exchangeRoundRobin(query, response, error, usedUpstream);
    }
    if (strategy_ == "fastest") {
        return exchangeFastest(query, response, error, usedUpstream);
    }
    if (strategy_ == "random") {
        return exchangeRandom(query, response, error, usedUpstream);
    }
    return exchangeFailover(query, response, error, usedUpstream);
}

bool Pool::exchangeFailover(const dns::Bytes& query, dns::Bytes& response, std::string& error, std::string& usedUpstream) {
    std::string lastError;
    for (Upstream* u : upstreams_) {
        if (u->exchange(query, response, lastError)) {
            usedUpstream = u->name();
            return true;
        }
    }
    error = allServersFailedError(lastError);
    return false;
}

bool Pool::exchangeRoundRobin(const dns::Bytes& query, dns::Bytes& response, std::string& error, std::string& usedUpstream) {
    const size_t start = counter_++ % upstreams_.size();
    std::string lastError;
    for (size_t i = 0; i < upstreams_.size(); ++i) {
        Upstream* u = upstreams_[(start + i) % upstreams_.size()];
        if (u->exchange(query, response, lastError)) {
            usedUpstream = u->name();
            return true;
        }
    }
    error = allServersFailedError(lastError);
    return false;
}

bool Pool::exchangeRandom(const dns::Bytes& query, dns::Bytes& response, std::string& error, std::string& usedUpstream) {
    std::vector<Upstream*> candidates = upstreams_;
    static thread_local std::mt19937 gen{std::random_device{}()};
    std::shuffle(candidates.begin(), candidates.end(), gen);

    std::string lastError;
    for (Upstream* u : candidates) {
        if (u->exchange(query, response, lastError)) {
            usedUpstream = u->name();
            return true;
        }
    }
    error = allServersFailedError(lastError);
    return false;
}

void Pool::refreshLatencies() {
    const auto now = std::chrono::steady_clock::now();
    if (now - lastLatencyCheck_ < std::chrono::seconds(60)) {
        return;
    }
    lastLatencyCheck_ = now;
    for (Upstream* u : upstreams_) {
        uint32_t rtt = 0;
        std::string err;
        if (u->ping(rtt, err)) {
            latencies_[u->name()] = rtt;
        } else {
            latencies_[u->name()] = 9999;
        }
    }
}

bool Pool::exchangeFastest(const dns::Bytes& query, dns::Bytes& response, std::string& error, std::string& usedUpstream) {
    std::vector<Upstream*> sorted;
    {
        std::lock_guard<std::mutex> lock(latencyMutex_);
        refreshLatencies();
        sorted = upstreams_;
        std::sort(sorted.begin(), sorted.end(), [this](Upstream* a, Upstream* b) {
            return latencies_[a->name()] < latencies_[b->name()];
        });
    }

    std::string lastError;
    for (Upstream* u : sorted) {
        if (u->exchange(query, response, lastError)) {
            usedUpstream = u->name();
            return true;
        }
    }
    error = allServersFailedError(lastError);
    return false;
}
