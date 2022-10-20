#pragma once

#include <g6/format.hpp>
#include <g6/from_string.hpp>

#include <g6/net/ipv4_address.hpp>

#include <optional>
#include <string>
#include <string_view>

namespace g6::net {
    class ipv4_endpoint {
    public:
        explicit constexpr ipv4_endpoint(ipv4_address address, std::uint16_t port = 0) noexcept
            : m_address(address), m_port(port) {}

        // Construct to 0.0.0.0:0
        constexpr ipv4_endpoint(std::uint16_t port = 0) noexcept : ipv4_endpoint{ipv4_address{}, port} {}

        [[nodiscard]] const ipv4_address &address() const noexcept { return m_address; }

        [[nodiscard]] std::uint16_t port() const noexcept { return m_port; }


        template<typename Context>
        friend auto tag_invoke(tag_t<g6::format_to>, ipv4_endpoint const &self, Context &ctx) noexcept {
            return g6::format_to(ctx.out(), "{}:{}", self.m_address, self.m_port);
        }

        friend std::optional<ipv4_endpoint> tag_invoke(tag_t<from_string<ipv4_endpoint>>,
                                                       std::string_view string) noexcept;

        bool operator==(const ipv4_endpoint &rhs) const noexcept = default;
        constexpr auto operator<=>(const ipv4_endpoint &rhs) const noexcept = default;

    private:
        ipv4_address m_address;
        std::uint16_t m_port;
    };

}// namespace g6::net
