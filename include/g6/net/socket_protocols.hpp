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
        constexpr socket_protocol tcp{AF_INET, SOCK_STREAM, IPPROTO_TCP};
        constexpr socket_protocol udp{AF_INET, SOCK_DGRAM, IPPROTO_UDP};
    }// namespace proto

}// namespace g6::net
