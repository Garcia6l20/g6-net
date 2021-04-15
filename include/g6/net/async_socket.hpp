#pragma once

#include <g6/net/net_cpo.hpp>

#include <g6/io/context.hpp>
#include <g6/net/ip_endpoint.hpp>

#include <span>

namespace g6::net {

    namespace detail {
        namespace tags {
            struct tcp_server {};
            struct tcp_client {};
        }// namespace tags

        struct accept_sender;
        struct connect_sender;
        struct recv_sender;
        struct recv_from_sender;
        struct send_sender;
        struct send_to_sender;
    }// namespace detail

    inline const detail::tags::tcp_server tcp_server;
    inline const detail::tags::tcp_client tcp_client;

    class async_socket
    {
    public:
        explicit async_socket(io::context &context, int fd) noexcept : context_(context), fd_(fd) {}

        async_socket(async_socket &&) = default;
        async_socket(async_socket const &) = delete;
        ~async_socket() = default;

        void bind(g6::net::ip_endpoint const &endpoint) {
            sockaddr_storage storage{};
            auto size = endpoint.to_sockaddr(storage);
            if (auto error = ::bind(fd_.get(), reinterpret_cast<const sockaddr *>(&storage), size); error < 0) {
                throw std::system_error(-errno, std::system_category());
            }
        }

        std::optional<net::ip_endpoint> local_endpoint() const {
            sockaddr sockaddr_in_{};
            socklen_t sockaddr_in_len = sizeof(sockaddr_in_);
            if (getsockname(fd_.get(), &sockaddr_in_, &sockaddr_in_len) < 0) { return std::nullopt; }
            return net::ip_endpoint::from_sockaddr(sockaddr_in_);
        }

        void listen(size_t count = 100) {
            if (::listen(fd_.get(), count) < 0) { throw std::system_error(-errno, std::system_category()); }
        }

        void close_send() {
            if (::shutdown(fd_.get(), SHUT_WR)) {
                throw std::system_error(errno, std::system_category(),
                                        "failed to close socket send stream: shutdown(SHUT_WR)");
            }
        }

        void close_recv() {
            if (::shutdown(fd_.get(), SHUT_RD)) {
                throw std::system_error(errno, std::system_category(),
                                        "failed to close socket recv stream: shutdown(SHUT_RD)");
            }
        }

        void close_send_recv() {
            if (::shutdown(fd_.get(), SHUT_RDWR)) {
                throw std::system_error(errno, std::system_category(),
                                        "failed to close socket send/recv stream: shutdown(SHUT_RDWR)");
            }
        }

        friend auto tag_invoke(tag_t<async_accept>, async_socket &socket) noexcept;

        friend auto tag_invoke(tag_t<async_connect>, async_socket &socket, ip_endpoint &&endpoint) noexcept;
        friend auto tag_invoke(tag_t<async_connect>, async_socket &socket, ip_endpoint const &endpoint) noexcept;

        friend auto tag_invoke(tag_t<async_send>, async_socket &socket, span<const std::byte> buffer) noexcept;

        friend auto tag_invoke(tag_t<async_recv>, async_socket &socket, span<std::byte> buffer) noexcept;

        friend auto tag_invoke(tag_t<async_send_to>, async_socket &socket, span<const std::byte> buffer,
                               net::ip_endpoint const &endpoint) noexcept;

        friend auto tag_invoke(tag_t<async_recv_from>, async_socket &socket, span<std::byte> buffer) noexcept;

        friend auto tag_invoke(tag_t<has_pending_data>, async_socket &socket) noexcept;

    protected:
        safe_file_descriptor fd_;
        io::context &context_;
    };

}// namespace g6::net

namespace g6::io {
    net::async_socket tag_invoke(tag_t<net::open_socket>, auto &ctx, int domain, int type, int proto = 0);
}// namespace g6::io

#include <g6/net/impl/async_socket_impl.hpp>
