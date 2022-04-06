#ifndef G6_NET_CPO_HPP_
#define G6_NET_CPO_HPP_

#include <cstring>

#include <utility>

#if G6_OS_WINDOWS
#include <WinSock2.h>
#else
#include <netdb.h>
#include <sys/socket.h>
#endif

#include <g6/net/ip_address.hpp>
#include <stdexcept>

namespace g6::net {

    template<typename Impl>
    class socket_option {
    public:
        template<typename Soket, typename... Args>
        static auto set(Soket &sock, Args &&...args) {
            return Impl::set_impl(sock.get_fd(), std::forward<Args>(args)...);
        }
        template<typename Soket>
        static auto get(Soket &sock) {
            return Impl::get_impl(sock.get_fd());
        }
    };

    template<int so_level, int opt_name, typename UserT = bool, typename ImplT = int>
    class simple_scoket_option : public socket_option<simple_scoket_option<so_level, opt_name, UserT, ImplT>> {
    private:
        friend class socket_option<simple_scoket_option<so_level, opt_name, UserT, ImplT>>;
        static void set_impl(auto fd, UserT value);
        template<typename... Args>
        static void set_impl(auto fd, Args &&...args) requires(std::is_constructible_v<UserT, Args...>) {
            set_impl(fd, UserT{std::forward<Args>(args)...});
        }
        static UserT get_impl(auto fd);
    };

    template<int so_level, int opt_name>
    class empty_socket_option : public socket_option<empty_socket_option<so_level, opt_name>> {
    private:
        friend class socket_option<empty_socket_option<so_level, opt_name>>;
        static void set_impl(auto fd);
        static void get_impl(auto fd);
    };

}// namespace g6::net

namespace g6::net::socket_options {
    using reuse_address = simple_scoket_option<SOL_SOCKET, SO_REUSEADDR>;
    using reuse_address_ex = simple_scoket_option<SOL_SOCKET, SO_EXCLUSIVEADDRUSE>;
    //using reuse_port = simple_option<SOL_SOCKET, SO_REUSEPORT>;

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
        using add_membership = simple_scoket_option<IPPROTO_IP, IP_ADD_MEMBERSHIP, membership, ip_mreq>;
        using multicast_loop = simple_scoket_option<IPPROTO_IP, IP_MULTICAST_LOOP>;
    }// namespace ip

}// namespace g6::net::socket_options

#include <g6/net/impl/socket_options_impl.hpp>

#endif// G6_NET_CPO_HPP_
