///////////////////////////////////////////////////////////////////////////////
// Kt C++ Library
// Copyright (c) 2015 Lewis Baker
///////////////////////////////////////////////////////////////////////////////

#include <cstdint>
#include <g6/net/ipv6_endpoint.hpp>

namespace g6::net {
    std::optional<ipv6_endpoint> tag_invoke(tag_t<from_string<ipv6_endpoint>>, std::string_view string) noexcept {
        // Shortest valid endpoint is "[::]:0"
        if (string.size() < 6) { return std::nullopt; }

        if (string[0] != '[') { return std::nullopt; }

        auto closeBracketPos = string.find("]:", 1);
        if (closeBracketPos == std::string_view::npos) { return std::nullopt; }

        auto address = g6::from_string<ipv6_address>(string.substr(1, closeBracketPos - 1));
        if (!address) { return std::nullopt; }

        auto port = g6::from_string<uint16_t>(string.substr(closeBracketPos + 2));
        if (!port) { return std::nullopt; }

        return ipv6_endpoint{*address, *port};
    }
}// namespace g6::net
