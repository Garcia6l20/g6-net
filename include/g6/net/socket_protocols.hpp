#pragma once

#include <g6/coro/config.hpp>

#if G6_OS_LINUX
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#endif

namespace g6::net {

    struct socket_protocol {
        int domain;
        int type;
        int proto;
    };
    namespace proto {
        struct tcp_t {
            constexpr operator socket_protocol() const noexcept {
                return {AF_INET, SOCK_STREAM, IPPROTO_TCP};
            }
        };
        constexpr tcp_t tcp;

        struct udp_t {
            constexpr operator socket_protocol() const noexcept {
                return {AF_INET, SOCK_DGRAM, IPPROTO_UDP};
            }
        };
        constexpr udp_t udp;
    }// namespace proto

}// namespace g6::net
