///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef G6_NET_IP_ENDPOINT_HPP_
#define G6_NET_IP_ENDPOINT_HPP_

#include <g6/net/ip_address.hpp>
#include <g6/net/ipv4_endpoint.hpp>
#include <g6/net/ipv6_endpoint.hpp>

#include <cassert>
#include <optional>
#include <string>
#include <type_traits>

#include <cstring>

#if defined(_MSC_VER)
#include <WinSock2.h>
#include <ws2ipdef.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif


namespace g6::net {
    class ip_endpoint
    {
    public:
        // Constructs to IPv4 end-point 0.0.0.0:0
        ip_endpoint() noexcept;

        ip_endpoint(ipv4_endpoint endpoint) noexcept;
        ip_endpoint(ipv6_endpoint endpoint) noexcept;

        [[nodiscard]] bool is_ipv4() const noexcept { return m_family == family::ipv4; }
        [[nodiscard]] bool is_ipv6() const noexcept { return m_family == family::ipv6; }

        [[nodiscard]] const ipv4_endpoint &to_ipv4() const;
        [[nodiscard]] const ipv6_endpoint &to_ipv6() const;

        [[nodiscard]] ip_address address() const noexcept;
        [[nodiscard]] std::uint16_t port() const noexcept;

        [[nodiscard]] std::string to_string() const;

        static std::optional<ip_endpoint>
        from_string(std::string_view string) noexcept;

        bool operator==(const ip_endpoint &rhs) const noexcept;
        bool operator!=(const ip_endpoint &rhs) const noexcept;

        //  ipv4_endpoint sorts less than ipv6_endpoint
        bool operator<(const ip_endpoint &rhs) const noexcept;
        bool operator>(const ip_endpoint &rhs) const noexcept;
        bool operator<=(const ip_endpoint &rhs) const noexcept;
        bool operator>=(const ip_endpoint &rhs) const noexcept;

        static ip_endpoint
        from_sockaddr(const sockaddr &address) noexcept {
            if (address.sa_family == AF_INET) {
                sockaddr_in ipv4Address{};
                std::memcpy(&ipv4Address, &address, sizeof(ipv4Address));

                std::uint8_t addressBytes[4];
                std::memcpy(addressBytes, &ipv4Address.sin_addr, 4);

                return ipv4_endpoint{
                    ipv4_address{addressBytes},
                    ntohs(ipv4Address.sin_port)};
            } else {
                assert(address.sa_family == AF_INET6);

                sockaddr_in6 ipv6Address{};
                std::memcpy(&ipv6Address, &address, sizeof(ipv6Address));

                return ipv6_endpoint{
                    ipv6_address{ipv6Address.sin6_addr.s6_addr},
                    ntohs(ipv6Address.sin6_port)};
            }
        }

        int to_sockaddr(sockaddr_storage& address) noexcept {
            if (is_ipv4()) {
                const auto &ipv4EndPoint = to_ipv4();

                sockaddr_in ipv4Address{};
                ipv4Address.sin_family = AF_INET;
                std::memcpy(&ipv4Address.sin_addr, ipv4EndPoint.address().bytes(), 4);
                ipv4Address.sin_port = htons(ipv4EndPoint.port());
                std::memset(&ipv4Address.sin_zero, 0, sizeof(ipv4Address.sin_zero));

                std::memcpy(&address, &ipv4Address, sizeof(ipv4Address));

                return sizeof(sockaddr_in);
            } else {
                const auto &ipv6EndPoint = to_ipv6();

                sockaddr_in6 ipv6Address{};
                ipv6Address.sin6_family = AF_INET6;
                std::memcpy(&ipv6Address.sin6_addr, ipv6EndPoint.address().bytes(), 16);
                ipv6Address.sin6_port = htons(ipv6EndPoint.port());
                ipv6Address.sin6_flowinfo = 0;
                ipv6Address.sin6_scope_id = 0;

                std::memcpy(&address, &ipv6Address, sizeof(ipv6Address));

                return sizeof(sockaddr_in6);
            }
        }

    private:
        enum class family
        {
            ipv4,
            ipv6
        };

        family m_family;

        union
        {
            ipv4_endpoint m_ipv4;
            ipv6_endpoint m_ipv6;
        };
    };

    inline ip_endpoint::ip_endpoint() noexcept
        : m_family(family::ipv4), m_ipv4() {}

    inline ip_endpoint::ip_endpoint(ipv4_endpoint endpoint) noexcept
        : m_family(family::ipv4), m_ipv4(endpoint) {}

    inline ip_endpoint::ip_endpoint(ipv6_endpoint endpoint) noexcept
        : m_family(family::ipv6), m_ipv6(endpoint) {
    }

    inline const ipv4_endpoint &ip_endpoint::to_ipv4() const {
        assert(is_ipv4());
        return m_ipv4;
    }

    inline const ipv6_endpoint &ip_endpoint::to_ipv6() const {
        assert(is_ipv6());
        return m_ipv6;
    }

    inline ip_address ip_endpoint::address() const noexcept {
        if (is_ipv4()) {
            return m_ipv4.address();
        } else {
            return m_ipv6.address();
        }
    }

    inline std::uint16_t ip_endpoint::port() const noexcept {
        return is_ipv4() ? m_ipv4.port() : m_ipv6.port();
    }

    inline bool ip_endpoint::operator==(const ip_endpoint &rhs) const noexcept {
        if (is_ipv4()) {
            return rhs.is_ipv4() && m_ipv4 == rhs.m_ipv4;
        } else {
            return rhs.is_ipv6() && m_ipv6 == rhs.m_ipv6;
        }
    }

    inline bool ip_endpoint::operator!=(const ip_endpoint &rhs) const noexcept {
        return !(*this == rhs);
    }

    inline bool ip_endpoint::operator<(const ip_endpoint &rhs) const noexcept {
        if (is_ipv4()) {
            return !rhs.is_ipv4() || m_ipv4 < rhs.m_ipv4;
        } else {
            return rhs.is_ipv6() && m_ipv6 < rhs.m_ipv6;
        }
    }

    inline bool ip_endpoint::operator>(const ip_endpoint &rhs) const noexcept {
        return rhs < *this;
    }

    inline bool ip_endpoint::operator<=(const ip_endpoint &rhs) const noexcept {
        return !(rhs < *this);
    }

    inline bool ip_endpoint::operator>=(const ip_endpoint &rhs) const noexcept {
        return !(*this < rhs);
    }
}// namespace g6::net

#endif // G6_NET_IP_ENDPOINT_HPP_
