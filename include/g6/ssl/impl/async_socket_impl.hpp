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
                                                                std::stop_token stop = {}) {
        auto [in_sock, endpoint] = co_await net::async_accept(static_cast<net::async_socket &>(socket), stop);
        ssl::async_socket ssl_sock{std::move(in_sock), ssl::async_socket::connection_mode::server, socket.certificate_,
                                   socket.key_};
        ssl_sock.host_name(socket.hostname_);
        ssl_sock.verify_flags_ = socket.verify_flags_;
        ssl_sock.verify_mode_ = socket.verify_mode_;
        co_await ssl::async_encrypt(ssl_sock, stop);
        co_return std::make_tuple(std::move(ssl_sock), std::move(endpoint));
    }

    task<void> tag_invoke(tag_t<net::async_connect>, ssl::async_socket &socket, const net::ip_endpoint &endpoint,
                          std::stop_token stop = {}) {
        co_await net::async_connect(static_cast<net::async_socket &>(socket), endpoint, stop);
        co_await ssl::async_encrypt(socket, stop);
    }

    task<void> tag_invoke(tag_t<ssl::async_encrypt>, ssl::async_socket &socket, std::stop_token stop = {}) {
        auto &net_sock = static_cast<net::async_socket &>(socket);
        auto *ssl_ctx = socket.ssl_context_.get();
        while ((not socket.encrypted_) and (not stop.stop_requested())) {
            int result = mbedtls_ssl_handshake(ssl_ctx);
            if (result == MBEDTLS_ERR_SSL_WANT_READ) {
                socket.to_receive_.actual_len = co_await net::async_recv(
                    net_sock, std::span{socket.to_receive_.buf, socket.to_receive_.len}, std::stop_token{stop});
            } else if (result == MBEDTLS_ERR_SSL_WANT_WRITE) {
                socket.to_send_.actual_len = co_await net::async_send(
                    net_sock, std::span{socket.to_send_.buf, socket.to_send_.len}, stop);
            } else if (result == MBEDTLS_ERR_ECP_VERIFY_FAILED) {
                if (uint32_t flags = mbedtls_ssl_get_verify_result(ssl_ctx); flags != 0) {
                    char vrfy_buf[1024];
                    int res = mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "", flags);
                    if (res < 0) {
                        throw std::system_error{res, ssl::error_category, "mbedtls_x509_crt_verify_info"};
                    } else if (res) {
                        throw std::system_error{MBEDTLS_ERR_ECP_VERIFY_FAILED, ssl::error_category,
                                                std::string{vrfy_buf, size_t(res - 1)}};
                    }
                }
                socket.encrypted_ = true;
            } else if (result != 0) {
                throw std::system_error(result, ssl::error_category, "mbedtls_ssl_handshake");
            } else {
                socket.encrypted_ = true;
            }
        }
    }

    task<size_t> tag_invoke(tag_t<net::async_recv>, ssl::async_socket &socket, std::span<std::byte> buffer,
                            std::stop_token stop = {}) {
        assert(socket.encrypted_);
        auto &net_sock = static_cast<net::async_socket &>(socket);
        auto *ssl_ctx = socket.ssl_context_.get();
        while (not stop.stop_requested()) {
            auto result = mbedtls_ssl_read(ssl_ctx, reinterpret_cast<uint8_t *>(buffer.data()), buffer.size());
            if (result == MBEDTLS_ERR_SSL_WANT_READ) {
                assert(socket.to_receive_);// ensure buffer/len properly setup
                socket.to_receive_.actual_len = co_await net::async_recv(
                    net_sock, std::span{socket.to_receive_.buf, socket.to_receive_.len}, stop);
            } else if (result == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                co_return 0;
            } else if (result < 0) {
                throw std::system_error(result, ssl::error_category, "mbedtls_ssl_read");
            } else {
                co_return result;
            }
        }
        co_return 0;
    }

    task<size_t> tag_invoke(tag_t<net::async_send>, ssl::async_socket &socket, std::span<const std::byte> buffer,
                            std::stop_token stop = {}) {
        assert(socket.encrypted_);
        auto &net_sock = static_cast<net::async_socket &>(socket);
        auto *ssl_ctx = socket.ssl_context_.get();
        size_t offset = 0;
        while ((not stop.stop_requested()) and (offset < buffer.size())) {
            int result = mbedtls_ssl_write(ssl_ctx, reinterpret_cast<const uint8_t *>(buffer.data()) + offset,
                                           buffer.size() - offset);
            if (result == MBEDTLS_ERR_SSL_WANT_WRITE) {
                assert(socket.to_send_);// ensure buffer/len properly setup
                socket.to_send_.actual_len = co_await net::async_send(
                    net_sock, std::span{socket.to_send_.buf, socket.to_send_.len}, stop);
            } else if (result < 0) {
                throw std::system_error(result, ssl::error_category, "mbedtls_ssl_write");
            } else {
                offset += result;
            }
        }
        co_return offset;
    }

}// namespace g6::ssl

namespace g6::io {
    ssl::async_socket tag_invoke(tag_t<net::open_socket> tag_t, auto &ctx, ssl::detail::tags::tcp_client tcp_tag) {
        return ssl::tag_invoke(tag_t, ctx, tcp_tag);
    }
}// namespace g6::io
