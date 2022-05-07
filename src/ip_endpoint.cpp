///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////

#include <g6/net/ip_endpoint.hpp>

std::string g6::net::ip_endpoint::to_string() const {
    auto s = addr_.to_string();
    s.push_back(':');
    s.append(std::to_string(port_));
    return s;
}

std::optional<g6::net::ip_endpoint> g6::net::ip_endpoint::from_string(std::string_view string) noexcept {
    if (auto ipv4 = ipv4_endpoint::from_string(string); ipv4) { return *ipv4; }

    if (auto ipv6 = ipv6_endpoint::from_string(string); ipv6) { return *ipv6; }

    return std::nullopt;
}
