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

    auto tag_invoke(tag_t<ssl::async_encrypt>, ssl::async_socket &socket) { return socket.handshake(); }

    auto tag_invoke(tag_t<net::async_accept>, ssl::async_socket &socket) {
        return let(net::async_accept(static_cast<net::async_socket &>(socket)), [&](auto &result) {
            auto &[in_sock, endpoint] = result;
            return let_with(
                [&] {
                    return std::optional{ssl::async_socket{std::forward<net::async_socket>(in_sock),
                                                           ssl::async_socket::connection_mode::server,
                                                           socket.certificate_, socket.key_}};
                },
                [&](auto &ssl_sock) {
                    ssl_sock->host_name(socket.host_name());
                    ssl_sock->verify_flags_ = socket.verify_flags_;
                    ssl_sock->verify_mode_ = socket.verify_mode_;
                    return ssl::async_encrypt(*ssl_sock)
                         | transform([&] { return std::make_tuple(std::move(ssl_sock).value(), std::move(endpoint)); });
                });
        });
    }

    auto tag_invoke(tag_t<net::async_connect>, ssl::async_socket &socket, const net::ip_endpoint &endpoint) {
        return let(net::async_connect(static_cast<net::async_socket &>(socket), endpoint),
                   [&](int result) { return ssl::async_encrypt(socket); });
    }

    auto tag_invoke(tag_t<net::async_send>, ssl::async_socket &socket, span<const std::byte> buffer) {
        return socket.send(buffer.data(), buffer.size());
    }

    auto tag_invoke(tag_t<net::async_recv>, ssl::async_socket &socket, span<std::byte> buffer) {
        return socket.recv(buffer.data(), buffer.size());
    }

}// namespace g6::ssl

namespace g6::io {
    ssl::async_socket tag_invoke(tag_t<net::open_socket> tag, auto &ctx, ssl::detail::tags::tcp_client tcp_tag) {
        return ssl::tag_invoke(tag, ctx, tcp_tag);
    }
//    auto tag_invoke(tag_t<net::async_connect>, auto &ctx, ssl::detail::tags::tcp_client tcp_tag,
//                    const net::ip_endpoint &endpoint, ssl::verify_flags verify_flags = ssl::verify_flags::none) {
//        return let(just(net::open_socket(ctx, tcp_tag)), [&](ssl::async_socket &ssl_sock) {
//            ssl_sock.set_verify_flags(verify_flags);
//            return net::async_connect(ssl_sock, endpoint) | transform([&] { return std::move(ssl_sock); });
//        });
//    }
}// namespace g6::io
