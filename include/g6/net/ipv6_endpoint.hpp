///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#pragma once

#include <g6/net/ipv6_address.hpp>

#include <optional>
#include <string>
#include <string_view>

namespace g6::net {
    class ipv6_endpoint
    {
    public:
        // Construct to [::]:0
        ipv6_endpoint() noexcept
            : m_address(), m_port(0) {}

        explicit ipv6_endpoint(ipv6_address address, std::uint16_t port = 0) noexcept
            : m_address(address), m_port(port) {}

        const ipv6_address &address() const noexcept { return m_address; }

        std::uint16_t port() const noexcept { return m_port; }

        std::string to_string() const;

        static std::optional<ipv6_endpoint> from_string(std::string_view string) noexcept;

    private:
        ipv6_address m_address;
        std::uint16_t m_port;
    };

    inline bool operator==(const ipv6_endpoint &a, const ipv6_endpoint &b) {
        return a.address() == b.address() &&
               a.port() == b.port();
    }

    inline bool operator!=(const ipv6_endpoint &a, const ipv6_endpoint &b) {
        return !(a == b);
    }

    inline bool operator<(const ipv6_endpoint &a, const ipv6_endpoint &b) {
        return a.address() < b.address() ||
               (a.address() == b.address() && a.port() < b.port());
    }

    inline bool operator>(const ipv6_endpoint &a, const ipv6_endpoint &b) {
        return b < a;
    }

    inline bool operator<=(const ipv6_endpoint &a, const ipv6_endpoint &b) {
        return !(b < a);
    }

    inline bool operator>=(const ipv6_endpoint &a, const ipv6_endpoint &b) {
        return !(a < b);
    }
}// namespace g6::net
