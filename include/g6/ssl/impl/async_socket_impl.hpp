#pragma once

#include <g6/ssl/async_socket.hpp>

#include <optional>

namespace g6::ssl {
    /** @brief Creates an SSL tcp server
     *
     * @param scheduler
     * @param certificate
     * @param pk
     * @return The created ssl::async_socket
     */
    ssl::async_socket tag_invoke(tag_t<net::open_socket>, auto &ctx, net::ip_endpoint const &endpoint,
                                 ssl::certificate const &certificate, ssl::private_key const &pk) {
#if G6_OS_WINDOWS
        auto [result, iocp_skip] = io::create_socket(net::proto::tcp, ctx.iocp_handle());
        if (result < 0) { throw std::system_error{static_cast<int>(::WSAGetLastError()), std::system_category()}; }
        ssl::async_socket sock{ctx,         result, net::proto::tcp, ssl::async_socket::connection_mode::server,
                               certificate, pk,     iocp_skip};
#else
        int result = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (result < 0) { throw std::system_error{-errno, std::system_category()}; }
        ssl::async_socket sock{ctx,         result, net::proto::tcp, ssl::async_socket::connection_mode::server,
                               certificate, pk};
#endif
        sock.bind(endpoint);
        sock.listen();
        return sock;
    }

    ssl::async_socket tag_invoke(tag_t<net::open_socket>, auto &ctx, ssl::detail::tags::tcp_client) {
#if G6_OS_WINDOWS
        auto [result, iocp_skip] = io::create_socket(net::proto::tcp, ctx.iocp_handle());
        if (result < 0) { throw std::system_error{static_cast<int>(::WSAGetLastError()), std::system_category()}; }
        ssl::async_socket sock{ctx, result, net::proto::tcp, ssl::async_socket::connection_mode::client,
                               {},  {},     iocp_skip};
#else
        int result = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (result < 0) {
            int errorCode = errno;
            throw std::system_error{errorCode, std::system_category()};
        }
        ssl::async_socket sock{ctx, result, net::proto::tcp, ssl::async_socket::connection_mode::client, {}, {}};
#endif
        return sock;
    }

    ssl::async_socket tag_invoke(tag_t<net::open_socket>, auto &ctx, ssl::detail::tags::tcp_server,
                                 ssl::certificate const &certificate, ssl::private_key const &pk) {
        int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (fd < 0) {
            int errorCode = errno;
            throw std::system_error{errorCode, std::system_category()};
        }
        return {ctx, fd, ssl::async_socket::connection_mode::client, certificate, pk};
    }

    task<std::tuple<async_socket, net::ip_endpoint>> tag_invoke(tag_t<net::async_accept>, ssl::async_socket &socket,
                                                                std::stop_token const &stop = {}) {
        auto [in_sock, endpoint] = co_await net::async_accept(static_cast<net::async_socket &>(socket), stop);
        ssl::async_socket ssl_sock{std::move(in_sock), ssl::async_socket::connection_mode::server, socket.certificate_,
                                   socket.key_};
        ssl_sock.host_name(socket.hostname_);
        ssl_sock.verify_flags_ = socket.verify_flags_;
        ssl_sock.verify_mode_ = socket.verify_mode_;
        co_await ssl::async_encrypt(ssl_sock);
        co_return std::make_tuple(std::move(ssl_sock), std::move(endpoint));
    }

    task<void> tag_invoke(tag_t<net::async_connect>, ssl::async_socket &socket, const net::ip_endpoint &endpoint) {
        co_await net::async_connect(static_cast<net::async_socket &>(socket), endpoint);
        co_await ssl::async_encrypt(socket);
    }

}// namespace g6::ssl

namespace g6::io {
    ssl::async_socket tag_invoke(tag_t<net::open_socket> tag_t, auto &ctx, ssl::detail::tags::tcp_client tcp_tag) {
        return ssl::tag_invoke(tag_t, ctx, tcp_tag);
    }
}// namespace g6::io
