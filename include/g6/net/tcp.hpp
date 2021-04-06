#pragma once

#include <g6/net/ip_endpoint.hpp>
#include <g6/net/async_socket.hpp>
#include <g6/net/net_cpo.hpp>

#include <unifex/transform.hpp>

namespace g6::net {

    template<class IOContext2>
    auto tag_invoke(unifex::tag_t<open_socket>, IOContext2 &ctx, detail::tags::tcp_server const &,
                    ip_endpoint &&endpoint) {
        auto sock = open_socket(ctx, AF_INET, SOCK_STREAM);
        sock.bind(std::forward<ip_endpoint>(endpoint));
        sock.listen();
        return sock;
    }

    template<class IOContext2>
    auto tag_invoke(unifex::tag_t<open_socket>, IOContext2 &ctx, detail::tags::tcp_client const &,
                    ip_endpoint const&endpoint) {
        auto sock = open_socket(ctx, AF_INET, SOCK_STREAM);
        int fd = sock.fd_.get();
        return transform(net::async_connect(ctx, fd, endpoint), [sock = std::move(sock)](int) mutable {
                     return std::move(sock);
                   });
    }
}// namespace g6::net
