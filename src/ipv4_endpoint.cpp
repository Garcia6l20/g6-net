///////////////////////////////////////////////////////////////////////////////
// Kt C++ Library
// Copyright (c) 2015 Lewis Baker
///////////////////////////////////////////////////////////////////////////////

#include <cstdint>
#include <g6/net/ipv4_endpoint.hpp>

namespace g6::net {

    std::optional<ipv4_endpoint> tag_invoke(tag_t<from_string<ipv4_endpoint>>, std::string_view string) noexcept {
        auto colonPos = string.find(':');
        if (colonPos == std::string_view::npos) { return std::nullopt; }

        auto address = g6::from_string<ipv4_address>(string.substr(0, colonPos));
        if (!address) { return std::nullopt; }

        auto port = g6::from_string<uint16_t>(string.substr(colonPos + 1));
        if (!port) { return std::nullopt; }

        return ipv4_endpoint{*address, *port};
    }
}// namespace g6::net
