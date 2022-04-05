#ifndef G6_NET_CPO_HPP_
#define G6_NET_CPO_HPP_

#include <cstring>

#include <utility>

#include <netdb.h>
#include <sys/socket.h>

#include <g6/net/ip_address.hpp>
#include <stdexcept>

namespace g6::net {
    class socket;

    template<typename T>
    class socket_option {
    protected:
        T value_;

    public:
        socket_option(T &&value) noexcept : value_{std::forward<T>(value)} {}
        virtual void operator()(socket &) = 0;

        friend socket;
    };

    template<int so_level, int opt_name, typename UserT = bool, typename ImplT = int>
    class simple_option : public socket_option<UserT> {
        void operator()(socket &sock) final;

    public:
        using socket_option<UserT>::socket_option;
    };

}// namespace g6::net

namespace g6::net::socket_options {
    using reuse_address = simple_option<SOL_SOCKET, SO_REUSEADDR>;
    using reuse_port = simple_option<SOL_SOCKET, SO_REUSEPORT>;

    namespace ip {
        class membership {
        public:
            membership(ipv4_address const &multicast_addr, ipv4_address const &local_address)
                : multicast_addr_{multicast_addr}, local_address_{local_address} {}

            explicit operator ip_mreq() {
                ip_mreq mreq{};
                std::memcpy(&mreq.imr_multiaddr.s_addr, multicast_addr_.bytes(), 4);
                std::memcpy(&mreq.imr_interface.s_addr, local_address_.bytes(), 4);
                return mreq;
            }

        private:
            ipv4_address multicast_addr_;
            ipv4_address local_address_;
        };
        using add_membership = simple_option<IPPROTO_IP, IP_ADD_MEMBERSHIP, membership, ip_mreq>;
        using multicast_loop = simple_option<IPPROTO_IP, IP_MULTICAST_LOOP>;
    }// namespace ip

}// namespace g6::net::socket_options

#endif// G6_NET_CPO_HPP_
