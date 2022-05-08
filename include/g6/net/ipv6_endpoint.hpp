#pragma once

#include <g6/format.hpp>
#include <g6/from_string.hpp>

#include <g6/net/ipv6_address.hpp>

#include <optional>
#include <string>
#include <string_view>

namespace g6::net {
    class ipv6_endpoint {
    public:
        // Construct to [::]:0
        ipv6_endpoint() noexcept : m_address(), m_port(0) {}

        explicit ipv6_endpoint(ipv6_address address, std::uint16_t port = 0) noexcept
            : m_address(address), m_port(port) {}

        const ipv6_address &address() const noexcept { return m_address; }

        std::uint16_t port() const noexcept { return m_port; }

        template<typename Context>
        friend auto tag_invoke(tag_t<g6::format_to>, ipv6_endpoint const &self, Context &ctx) noexcept {
            return g6::format_to(ctx.out(), "[{}]:{}", self.m_address, self.m_port);
        }

        friend std::optional<ipv6_endpoint> tag_invoke(tag_t<from_string<ipv6_endpoint>>,
                                                       std::string_view string) noexcept;

        bool operator==(const ipv6_endpoint &rhs) const noexcept = default;
        constexpr auto operator<=>(const ipv6_endpoint &rhs) const noexcept = default;

    private:
        ipv6_address m_address;
        std::uint16_t m_port;
    };

}// namespace g6::net
