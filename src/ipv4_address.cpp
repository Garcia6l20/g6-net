#include <g6/net/ipv4_address.hpp>

#include <ctre.hpp>

namespace g6::net {
    std::optional<g6::net::ipv4_address> tag_invoke(tag_t<g6::from_string<ipv4_address>>,
                                                    std::string_view string) noexcept {
        if (auto [m, b1, b2, b3, b4] = ctre::match<R"(^([0-9]{1,3}).([0-9]{1,3}).([0-9]{1,3}).([0-9]{1,3})$)">(string);
            m) {
            uint8_t bytes[] = {*g6::from_string<uint8_t>(b1.to_view()),//
                               *g6::from_string<uint8_t>(b2.to_view()),//
                               *g6::from_string<uint8_t>(b3.to_view()),//
                               *g6::from_string<uint8_t>(b4.to_view())};
            return ipv4_address{bytes};
        }
        return std::nullopt;
    }
}// namespace g6::net
