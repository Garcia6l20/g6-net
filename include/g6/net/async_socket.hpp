#pragma once

#include <g6/net/net_cpo.hpp>

#include <g6/io/context.hpp>

#include <g6/net/ip_endpoint.hpp>
#include <g6/net/socket_options.hpp>
#include <g6/net/socket_protocols.hpp>


#include <span>

namespace g6::net {

    namespace detail {

#if G6_OS_WINDOWS
        template<typename Operation>
        class wsa_operation_base;
#endif

        class accept_sender;
        class connect_sender;
        class recv_sender;
        class recv_from_sender;
        class send_sender;
        class send_to_sender;
    }// namespace detail

    class async_socket {
        friend class detail::send_to_sender;
        friend class detail::send_sender;
        friend class detail::recv_from_sender;
        friend class detail::recv_sender;
        friend class detail::accept_sender;
        friend class detail::connect_sender;

#if G6_OS_WINDOWS
        template<typename Operation>
        friend class detail::wsa_operation_base;
#endif

    public:
#if G6_OS_WINDOWS
        using socket_handle = safe_handle<SOCKET, closesocket, INVALID_SOCKET>;
#else
        using socket_handle = safe_handle<int, ::close, -1>;
#endif
        explicit async_socket(io::context &context, socket_handle::handle_t fd, socket_protocol type,
                              bool skip_completion = false) noexcept
            : context_{context}, fd_{fd}, type_{type}, skip_completion_{skip_completion} {}

        async_socket(async_socket &&) = default;
        async_socket(async_socket const &) = delete;
        ~async_socket() = default;

        bool operator==(async_socket const &other) const noexcept { return other.fd_.get() == fd_.get(); }
        constexpr auto operator<=>(async_socket const &) const noexcept = default;

        void bind(g6::net::ip_endpoint const &endpoint) {
            sockaddr_storage storage{};
            auto size = endpoint.to_sockaddr(storage);
            if (auto error = ::bind(fd_.get(), reinterpret_cast<const sockaddr *>(&storage), size); error < 0) {
                throw std::system_error(errno, std::system_category());
            }
        }

        std::optional<net::ip_endpoint> local_endpoint() const {
            sockaddr_storage sockaddr_in_{};
#if G6_OS_WINDOWS
            int
#else
            socklen_t
#endif
                sockaddr_in_len = sizeof(sockaddr_in_);
            if (getsockname(fd_.get(), reinterpret_cast<sockaddr*>(&sockaddr_in_), &sockaddr_in_len) < 0) { return std::nullopt; }
            return net::ip_endpoint::from_sockaddr(sockaddr_in_);
        }

        std::optional<net::ip_endpoint> remote_endpoint() const {
            sockaddr_storage sockaddr_in_{};
#if G6_OS_WINDOWS
            int
#else
            socklen_t
#endif
                sockaddr_in_len = sizeof(sockaddr_in_);
            if (getpeername(fd_.get(), reinterpret_cast<sockaddr*>(&sockaddr_in_), &sockaddr_in_len) < 0) { return std::nullopt; }
            return net::ip_endpoint::from_sockaddr(sockaddr_in_);
        }

        socket_protocol protocol() const noexcept { return type_; }

        void listen(size_t count = 100) {
#if G6_OS_WINDOWS
            if (::listen(fd_.get(), int(count)) < 0) {
#else
            if (::listen(fd_.get(), count) < 0) {
#endif
                throw std::system_error(errno, std::system_category());
            }
        }

        template<typename Opt, typename... Args>
        auto setopt(Args &&...args) const {
            Opt::set(*this, std::forward<Args>(args)...);
        }

        template<typename Opt>
        auto getopt() const {
            return Opt::get(*this);
        }

        auto get_fd() const noexcept { return fd_.get(); }

        void close_send() {
#if G6_OS_WINDOWS
            const int how = SD_SEND;
#else
            const int how = SHUT_WR;
#endif
            if (::shutdown(fd_.get(), how)) {
                throw std::system_error(errno, std::system_category(),
                                        "failed to close socket send stream: shutdown(SHUT_WR)");
            }
        }

        void close_recv() {
#if G6_OS_WINDOWS
            const int how = SD_RECEIVE;
#else
            const int how = SHUT_RD;
#endif
            if (::shutdown(fd_.get(), how)) {
                throw std::system_error(errno, std::system_category(),
                                        "failed to close socket recv stream: shutdown(SHUT_RD)");
            }
        }

        void close_send_recv() {
#if G6_OS_WINDOWS
            const int how = SD_BOTH;
#else
            const int how = SHUT_RDWR;
#endif
            if (::shutdown(fd_.get(), how)) {
                throw std::system_error(errno, std::system_category(),
                                        "failed to close socket send/recv stream: shutdown(SHUT_RDWR)");
            }
        }

        friend auto tag_invoke(tag_t<async_accept>, async_socket &socket) noexcept;

        friend auto tag_invoke(tag_t<async_connect>, async_socket &socket, ip_endpoint const &endpoint) noexcept;

        friend auto tag_invoke(tag_t<async_send>, async_socket &socket, std::span<const std::byte> buffer) noexcept;

        friend auto tag_invoke(tag_t<async_recv>, async_socket &socket, std::span<std::byte> buffer) noexcept;

        friend auto tag_invoke(tag_t<async_send_to>, async_socket &socket, std::span<const std::byte> buffer,
                               net::ip_endpoint const &endpoint) noexcept;

        friend auto tag_invoke(tag_t<async_recv_from>, async_socket &socket, std::span<std::byte> buffer) noexcept;

        friend auto tag_invoke(tag_t<pending_bytes>, async_socket &socket) noexcept;

        friend auto tag_invoke(tag_t<has_pending_data>, async_socket &socket) noexcept;

    protected:
        socket_handle fd_;
        io::context &context_;
        socket_protocol type_;
        bool skip_completion_;
    };

}// namespace g6::net


#include <g6/net/impl/async_socket_impl.hpp>
