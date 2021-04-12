#pragma once

#include <unifex/just.hpp>
#include <unifex/let.hpp>
#include <unifex/let_with.hpp>
#include <unifex/repeat_effect_until.hpp>
#include <unifex/sequence.hpp>

#include <optional>

namespace g6::ssl {
    /** @brief Creates an SSL tcp server
     *
     * @param scheduler
     * @param certificate
     * @param pk
     * @return The created ssl::async_socket
     */
    ssl::async_socket tag_invoke(tag_t<net::open_socket>, auto &ctx, ssl::detail::tags::tcp_server,
                                 net::ip_endpoint const &endpoint, ssl::certificate const &certificate,
                                 ssl::private_key const &pk) {
        int result = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (result < 0) {
            int errorCode = errno;
            throw_(std::system_error{errorCode, std::system_category()});
        }
        ssl::async_socket sock{ctx, result, ssl::async_socket::connection_mode::server, certificate, pk};
        sock.bind(endpoint);
        sock.listen();
        return sock;
    }

    ssl::async_socket tag_invoke(tag_t<net::open_socket>, auto &ctx, ssl::detail::tags::tcp_client) {
        int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (fd < 0) {
            int errorCode = errno;
            throw_(std::system_error{errorCode, std::system_category()});
        }
        return {ctx, fd, ssl::async_socket::connection_mode::client, {}, {}};
    }

    ssl::async_socket tag_invoke(tag_t<net::open_socket>, auto &ctx, ssl::detail::tags::tcp_client,
                                 ssl::certificate const &certificate, ssl::private_key const &pk) {
        int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (fd < 0) {
            int errorCode = errno;
            throw_(std::system_error{errorCode, std::system_category()});
        }
        return {ctx, fd, ssl::async_socket::connection_mode::client, certificate, pk};
    }

    auto tag_invoke(tag_t<net::async_connect>, ssl::async_socket &socket, const net::ip_endpoint &endpoint) {
        return let(net::async_connect(static_cast<net::async_socket &>(socket), endpoint),
                   [&](int result) { return ssl::async_encrypt(socket); });
    }

}// namespace g6::ssl

namespace g6::io {
    ssl::async_socket tag_invoke(tag_t<net::open_socket> tag, auto &ctx, ssl::detail::tags::tcp_client tcp_tag) {
        return ssl::tag_invoke(tag, ctx, tcp_tag);
    }
}// namespace g6::io
