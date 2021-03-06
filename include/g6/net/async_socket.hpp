#ifndef G6_NET_ASYNC_SOCKET_HPP_
#define G6_NET_ASYNC_SOCKET_HPP_

#include <g6/io/context.hpp>
#include <g6/net/ip_endpoint.hpp>
#include <g6/net/net_cpo.hpp>

#include <span>

namespace g6::net {

    namespace detail {
        struct accept_sender;
        struct connect_sender;
        struct recv_sender;
        struct recv_from_sender;
        struct send_sender;
        struct send_to_sender;
    }

    class async_socket
    {
    public:
        explicit async_socket(io::context &context, int fd) noexcept
            : context_(context), fd_(fd) {}

        void bind(g6::net::ip_endpoint &&endpoint) {
            sockaddr_storage storage{};
            auto size = endpoint.to_sockaddr(storage);
            if (auto error = ::bind(fd_.get(), reinterpret_cast<const sockaddr *>(&storage), size);
                error < 0) {
                throw std::system_error(-errno, std::system_category());
            }
        }

        void listen(size_t count = 100) {
            if (::listen(fd_.get(), count) < 0) {
                throw std::system_error(-errno, std::system_category());
            }
        }

        friend auto tag_invoke(
            tag_t<async_accept>,
            async_socket &socket) noexcept;

        friend auto tag_invoke(
            tag_t<async_connect>,
            async_socket &socket,
            ip_endpoint &&endpoint) noexcept;

        friend auto tag_invoke(
            tag_t<async_send>,
            async_socket &socket,
            span<const std::byte> buffer) noexcept;

        friend auto tag_invoke(
            tag_t<async_recv>,
            async_socket &socket,
            span<std::byte> buffer) noexcept;

        friend auto tag_invoke(
            tag_t<async_send_to>,
            async_socket &socket,
            span<const std::byte> buffer,
            net::ip_endpoint &&endpoint) noexcept;

        friend auto tag_invoke(
            tag_t<async_recv_from>,
            async_socket &socket,
            span<std::byte> buffer) noexcept;

    protected:
        safe_file_descriptor fd_;
        io::context &context_;
    };

}// namespace g6::net

namespace g6::io {
    net::async_socket tag_invoke(
        tag_t<net::open_socket>,
        auto scheduler,
        int domain, int type, int proto = 0);
}// namespace g6::io

#include <g6/net/impl/async_socket_impl.hpp>

#endif // G6_NET_ASYNC_SOCKET_HPP_
