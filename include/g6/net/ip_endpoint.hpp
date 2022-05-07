///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#pragma once

#include <g6/config.hpp>

#if G6_OS_WINDOWS
#define NOMINMAX
#include <WinSock2.h>
#include <ws2ipdef.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include <g6/net/ip_address.hpp>
#include <g6/net/ipv4_endpoint.hpp>
#include <g6/net/ipv6_endpoint.hpp>

#include <cassert>
#include <cinttypes>
#include <optional>
#include <string>
#include <type_traits>


#include <cstring>


namespace g6::net {
    class ip_endpoint {
    public:
        // Constructs to IPv4 end-point 0.0.0.0:0
        ip_endpoint() noexcept;

        ip_endpoint(ip_address address, uint16_t port = 0) noexcept;

        ip_endpoint(ipv4_endpoint endpoint) noexcept;
        ip_endpoint(ipv6_endpoint endpoint) noexcept;

        [[nodiscard]] bool is_ipv4() const noexcept { return addr_.is_ipv4(); }
        [[nodiscard]] bool is_ipv6() const noexcept { return addr_.is_ipv6(); }

        [[nodiscard]] ip_address const &address() const noexcept;
        [[nodiscard]] std::uint16_t port() const noexcept;

        [[nodiscard]] std::string to_string() const;

        static std::optional<ip_endpoint> from_string(std::string_view string) noexcept;

        bool operator==(const ip_endpoint &rhs) const noexcept;
        bool operator!=(const ip_endpoint &rhs) const noexcept;

        //  ipv4_endpoint sorts less than ipv6_endpoint
        bool operator<(const ip_endpoint &rhs) const noexcept;
        bool operator>(const ip_endpoint &rhs) const noexcept;
        bool operator<=(const ip_endpoint &rhs) const noexcept;
        bool operator>=(const ip_endpoint &rhs) const noexcept;

        static ip_endpoint from_sockaddr(const sockaddr &address) noexcept {
            if (address.sa_family == AF_INET) {
                sockaddr_in ipv4Address{};
                std::memcpy(&ipv4Address, &address, sizeof(ipv4Address));

                std::uint8_t addressBytes[4];
                std::memcpy(addressBytes, &ipv4Address.sin_addr, 4);

                return ipv4_endpoint{ipv4_address{addressBytes}, ntohs(ipv4Address.sin_port)};
            } else {
                assert(address.sa_family == AF_INET6);

                sockaddr_in6 ipv6Address{};
                std::memcpy(&ipv6Address, &address, sizeof(ipv6Address));

                return ipv6_endpoint{ipv6_address{ipv6Address.sin6_addr.s6_addr}, ntohs(ipv6Address.sin6_port)};
            }
        }

        int to_sockaddr(sockaddr_storage &address) const noexcept {
            if (is_ipv4()) {
                const auto &ipv4addr = addr_.to_ipv4();

                sockaddr_in ipv4Address{};
                ipv4Address.sin_family = AF_INET;
                std::memcpy(&ipv4Address.sin_addr, ipv4addr.bytes(), 4);
                ipv4Address.sin_port = htons(port_);
                std::memset(&ipv4Address.sin_zero, 0, sizeof(ipv4Address.sin_zero));

                std::memcpy(&address, &ipv4Address, sizeof(ipv4Address));

                return sizeof(sockaddr_in);
            } else {
                const auto &ipv6addr = addr_.to_ipv6();

                sockaddr_in6 ipv6Address{};
                ipv6Address.sin6_family = AF_INET6;
                std::memcpy(&ipv6Address.sin6_addr, ipv6addr.bytes(), 16);
                ipv6Address.sin6_port = htons(port_);
                ipv6Address.sin6_flowinfo = 0;
                ipv6Address.sin6_scope_id = 0;

                std::memcpy(&address, &ipv6Address, sizeof(ipv6Address));

                return sizeof(sockaddr_in6);
            }
        }

    private:
        ip_address addr_;
        uint16_t port_;
    };

    inline ip_endpoint::ip_endpoint() noexcept : addr_{ipv4_address{}} {}

    inline ip_endpoint::ip_endpoint(ipv4_endpoint endpoint) noexcept : addr_(endpoint.address()) {}

    inline ip_endpoint::ip_endpoint(ipv6_endpoint endpoint) noexcept : addr_(endpoint.address()) {}

    inline ip_endpoint::ip_endpoint(ip_address address, uint16_t port) noexcept : addr_{address}, port_{port} {}

    inline ip_address const &ip_endpoint::address() const noexcept { return addr_; }

    inline std::uint16_t ip_endpoint::port() const noexcept { return port_; }

    inline bool ip_endpoint::operator==(const ip_endpoint &rhs) const noexcept {
        return port_ == rhs.port_ and addr_ == rhs.addr_;
    }

    inline bool ip_endpoint::operator!=(const ip_endpoint &rhs) const noexcept { return !(*this == rhs); }

    inline bool ip_endpoint::operator<(const ip_endpoint &rhs) const noexcept {
        return port_ < rhs.port_ or addr_ < rhs.addr_;
    }

    inline bool ip_endpoint::operator>(const ip_endpoint &rhs) const noexcept { return rhs < *this; }

    inline bool ip_endpoint::operator<=(const ip_endpoint &rhs) const noexcept { return !(rhs < *this); }

    inline bool ip_endpoint::operator>=(const ip_endpoint &rhs) const noexcept { return !(*this < rhs); }
}// namespace g6::net
