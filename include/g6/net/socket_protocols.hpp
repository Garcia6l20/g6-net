#pragma once

namespace g6::net {

    struct socket_protocol {
        int domain;
        int type;
        int proto;
    };
    namespace protos {
        constexpr socket_protocol tcp{AF_INET, SOCK_STREAM, IPPROTO_TCP};
        constexpr socket_protocol udp{AF_INET, SOCK_DGRAM, IPPROTO_UDP};
    }// namespace protos

}// namespace g6::net
