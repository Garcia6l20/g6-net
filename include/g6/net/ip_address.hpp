#pragma once

#include <g6/format.hpp>
#include <g6/from_string.hpp>

#include <g6/net/ipv4_address.hpp>
#include <g6/net/ipv6_address.hpp>

#include <cassert>
#include <optional>
#include <string>
#include <string_view>

namespace g6::net {
    class ip_address {
    public:
        enum class family { ipv4, ipv6 };

    private:
        family m_family;

    public:
        // Constructs to IPv4 address 0.0.0.0
        ip_address() noexcept;

        ip_address(ipv4_address address) noexcept;
        ip_address(ipv6_address address) noexcept;

        family family() const noexcept { return m_family; }
        [[nodiscard]] bool is_ipv4() const noexcept { return m_family == family::ipv4; }
        [[nodiscard]] bool is_ipv6() const noexcept { return m_family == family::ipv6; }

        [[nodiscard]] const ipv4_address &to_ipv4() const;
        [[nodiscard]] const ipv6_address &to_ipv6() const;

        [[nodiscard]] const std::uint8_t *bytes() const noexcept;

        friend std::optional<ip_address> tag_invoke(tag_t<g6::from_string<ip_address>>,
                                                    std::string_view string) noexcept;

        template<typename Context>
        friend auto tag_invoke(tag_t<g6::format_to>, ip_address const &self, Context &ctx) noexcept {
            if (self.is_ipv4()) {
                return g6::format_to(ctx.out(), "{}", self.m_ipv4);
            } else {
                return g6::format_to(ctx.out(), "{}", self.m_ipv6);
            }
        }


        bool operator==(const ip_address &rhs) const noexcept = default;
        constexpr auto operator<=>(const ip_address &rhs) const noexcept = default;

    private:
        union {
            ipv4_address m_ipv4;
            ipv6_address m_ipv6;
        };
    };

    inline ip_address::ip_address() noexcept : m_family(family::ipv4), m_ipv4() {}

    inline ip_address::ip_address(ipv4_address address) noexcept : m_family(family::ipv4), m_ipv4(address) {}

    inline ip_address::ip_address(ipv6_address address) noexcept : m_family(family::ipv6), m_ipv6(address) {}

    inline const ipv4_address &ip_address::to_ipv4() const {
        assert(is_ipv4());
        return m_ipv4;
    }

    inline const ipv6_address &ip_address::to_ipv6() const {
        assert(is_ipv6());
        return m_ipv6;
    }

    inline const std::uint8_t *ip_address::bytes() const noexcept {
        return is_ipv4() ? m_ipv4.bytes() : m_ipv6.bytes();
    }

}// namespace g6::net
