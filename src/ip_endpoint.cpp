#include <g6/net/ip_endpoint.hpp>

namespace g6::net {
    std::optional<ip_endpoint> tag_invoke(tag_t<g6::from_string<ip_endpoint>>, std::string_view string) noexcept {
        if (auto ipv4 = g6::from_string<ipv4_endpoint>(string); ipv4) { return *ipv4; }
        if (auto ipv6 = g6::from_string<ipv6_endpoint>(string); ipv6) { return *ipv6; }
        return std::nullopt;
    }
}// namespace g6::net
