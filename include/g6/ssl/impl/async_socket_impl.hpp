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
    ssl::async_socket tag_invoke(tag<net::open_socket>, auto &ctx, net::ip_endpoint const &endpoint,
                                 ssl::certificate const &certificate, ssl::private_key const &pk) {
#if G6_OS_WINDOWS
        auto [result, iocp_skip] = io::create_socket(net::protos::tcp, ctx.iocp_handle());
        if (result < 0) { throw std::system_error{static_cast<int>(::WSAGetLastError()), std::system_category()}; }
        ssl::async_socket sock{ctx,         result, net::protos::tcp, ssl::async_socket::connection_mode::server,
                               certificate, pk,     iocp_skip};
#else
        int result = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (result < 0) { throw std::system_error{-errno, std::system_category()}; }
        ssl::async_socket sock{ctx,         result, net::protos::tcp, ssl::async_socket::connection_mode::server,
                               certificate, pk};
#endif
        sock.bind(endpoint);
        sock.listen();
        return sock;
    }

    ssl::async_socket tag_invoke(tag<net::open_socket>, auto &ctx, ssl::detail::tags::tcp_client) {
#if G6_OS_WINDOWS
        auto [result, iocp_skip] = io::create_socket(net::protos::tcp, ctx.iocp_handle());
        if (result < 0) { throw std::system_error{static_cast<int>(::WSAGetLastError()), std::system_category()}; }
        ssl::async_socket sock{ctx, result, net::protos::tcp, ssl::async_socket::connection_mode::client,
                               {},  {},     iocp_skip};
#else
        int result = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (result < 0) {
            int errorCode = errno;
            throw std::system_error{errorCode, std::system_category()};
        }
        ssl::async_socket sock{ctx, result, net::protos::tcp, ssl::async_socket::connection_mode::client, {}, {}};
#endif
        return sock;
    }

    ssl::async_socket tag_invoke(tag<net::open_socket>, auto &ctx, ssl::detail::tags::tcp_server,
                                 ssl::certificate const &certificate, ssl::private_key const &pk) {
        int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (fd < 0) {
            int errorCode = errno;
            throw std::system_error{errorCode, std::system_category()};
        }
        return {ctx, fd, ssl::async_socket::connection_mode::client, certificate, pk};
    }

    task<void> tag_invoke(tag<net::async_connect>, ssl::async_socket &socket, const net::ip_endpoint &endpoint) {
        co_await net::async_connect(static_cast<net::async_socket &>(socket), endpoint);
        co_await ssl::async_encrypt(socket);
    }

}// namespace g6::ssl

namespace g6::io {
    ssl::async_socket tag_invoke(tag<net::open_socket> tag, auto &ctx, ssl::detail::tags::tcp_client tcp_tag) {
        return ssl::tag_invoke(tag, ctx, tcp_tag);
    }
}// namespace g6::io
