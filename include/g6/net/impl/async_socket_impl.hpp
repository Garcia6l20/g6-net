#ifndef G6_NET_IMPL_ASYNC_SOCKET_HPP_
#define G6_NET_IMPL_ASYNC_SOCKET_HPP_

#include <g6/net/async_socket.hpp>

namespace g6::net::detail {
    struct accept_sender : io::context::base_sender {
        accept_sender(io::context &context, int fd) noexcept
            : io::context::base_sender{context, fd} {
            io_data_ = std::as_bytes(std::span{&sockaddr_storage_, 1});
        }

        template<typename Receiver>
        struct operation : io::context::base_operation<IORING_OP_ACCEPT, Receiver, operation<Receiver>> {
            using base = io::context::base_operation<IORING_OP_ACCEPT, Receiver, operation<Receiver>>;
            using base::base;
            auto get_io_data() noexcept {
                socklen_ = this->io_data_.size();
                return std::tuple{this->io_data_.data(), 0, reinterpret_cast<uint64_t>(&socklen_)};
            }
            auto get_result() noexcept {
                int fd = this->result_;
                return std::tuple{async_socket(this->context_, fd),
                                  ip_endpoint::from_sockaddr(*reinterpret_cast<const sockaddr *>(this->io_data_.data()))};
            }
            socklen_t socklen_{};
        };

        // Produces void result.
        template<
            template<typename...> class Variant,
            template<typename...> class Tuple>
        using value_types = Variant<Tuple<async_socket, ip_endpoint>>;

        template<template<typename...> class Variant>
        using error_types = Variant<std::error_code, std::exception_ptr>;

        template<typename Receiver>
        auto connect(Receiver &&r) && {
            return operation<Receiver>{*this, (Receiver &&) r};
        }

        sockaddr_storage sockaddr_storage_{};
        std::span<std::byte const> io_data_{};
        static constexpr int64_t offset_{0};
    };

    struct connect_sender : io::context::base_sender {
        connect_sender(io::context &context, int fd, ip_endpoint &&endpoint) noexcept
            : io::context::base_sender{context, fd} {
            auto len = endpoint.to_sockaddr(sockaddr_storage_);
            io_data_ = std::as_bytes(std::span{reinterpret_cast<std::byte *>(&sockaddr_storage_), size_t(len)});
        }

        template<typename Receiver>
        struct operation : io::context::base_operation<IORING_OP_CONNECT, Receiver, operation<Receiver>> {
            using base = io::context::base_operation<IORING_OP_CONNECT, Receiver, operation<Receiver>>;
            using base::base;
            auto get_io_data() noexcept {
                return std::tuple{this->io_data_.data(), 0, this->io_data_.size()};
            }
        };

        // Produces int result.
        template<
            template<typename...> class Variant,
            template<typename...> class Tuple>
        using value_types = Variant<Tuple<int>>;

        template<template<typename...> class Variant>
        using error_types = Variant<std::error_code, std::exception_ptr>;

        template<typename Receiver>
        auto connect(Receiver &&r) && {
            return operation<Receiver>{*this, (Receiver &&) r};
        }

        sockaddr_storage sockaddr_storage_{};
        std::span<std::byte const> io_data_{};
        static constexpr int64_t offset_{0};
    };

    struct send_sender : io::context::base_sender {
        send_sender(io::context &context, int fd, std::span<std::byte const> buffer) noexcept
            : io::context::base_sender{context, fd}, io_data_{buffer} {
        }

        template<typename Receiver>
        using operation = io::context::base_operation<IORING_OP_SEND, Receiver>;

        template<typename Receiver>
        auto connect(Receiver &&r) && {
            return operation<Receiver>{*this, (Receiver &&) r};
        }

        std::span<std::byte const> io_data_{};
        static constexpr int64_t offset_{0};
    };

    struct recv_sender : io::context::base_sender {
        recv_sender(io::context &context, int fd, std::span<std::byte> buffer) noexcept
            : io::context::base_sender{context, fd}, io_data_{buffer} {
        }

        template<typename Receiver>
        using operation = io::context::base_operation<IORING_OP_RECV, Receiver>;

        template<typename Receiver>
        auto connect(Receiver &&r) && {
            return operation<Receiver>{*this, (Receiver &&) r};
        }

        std::span<std::byte> io_data_{};
        static constexpr int64_t offset_{0};
    };

    template<uint8_t op_code>
    struct msg_sender : io::context::base_sender {

        template<typename Receiver>
        struct operation_type : io::context::base_operation<op_code, Receiver> {
            using io::context::base_operation<op_code, Receiver>::base_operation;
        };

        explicit msg_sender(io::context &ctx, int fd,
                            int64_t offset,
                            span<const std::byte> buffer,
                            std::optional<net::ip_endpoint> endpoint = {})
            : io::context::base_sender{ctx, fd}, offset_{offset}, iovec_{const_cast<std::byte *>(buffer.data()), buffer.size()} {
            if (endpoint)
                msghdr_.msg_namelen = endpoint->to_sockaddr(sockaddr_storage_);
        }

        template<typename Receiver>
        auto connect(Receiver &&r) && {
            return operation_type<Receiver>{*this, (Receiver &&) r};
        }

        int64_t offset_ = 0;
        sockaddr_storage sockaddr_storage_{};
        iovec iovec_;
        msghdr msghdr_{&sockaddr_storage_, sizeof(sockaddr_storage_), &iovec_, 1};
        const std::span<std::byte const> io_data_{std::as_bytes(std::span{reinterpret_cast<std::byte *>(&msghdr_), 1})};
    };

    struct send_to_sender : msg_sender<IORING_OP_SENDMSG> {
        using msg_sender<IORING_OP_SENDMSG>::msg_sender;
    };

    template<typename Receiver>
    struct recv_from_operation : io::context::base_operation<IORING_OP_RECVMSG, Receiver, recv_from_operation<Receiver>> {
        using base = io::context::base_operation<IORING_OP_RECVMSG, Receiver, recv_from_operation<Receiver>>;
        using base::base;

        explicit recv_from_operation(const auto &sender, auto &&r)
            : base{sender, std::forward<decltype(r)>(r)}, sockaddr_storage_{sender.sockaddr_storage_} {
        }

        auto get_result() noexcept {
            return std::make_tuple(size_t(this->result_),
                                   ip_endpoint::from_sockaddr(reinterpret_cast<const sockaddr &>(sockaddr_storage_)));
        }

        sockaddr_storage const &sockaddr_storage_;
    };

    struct recv_from_sender : msg_sender<IORING_OP_RECVMSG> {

        // Produces number of bytes read.
        template<
            template<typename...> class Variant,
            template<typename...> class Tuple>
        using value_types = Variant<Tuple<size_t, ip_endpoint>>;

        explicit recv_from_sender(io::context &ctx, int fd,
                                  int64_t offset,
                                  span<std::byte> buffer)
            : msg_sender<IORING_OP_RECVMSG>{ctx, fd, offset, buffer} {}

        template<typename Receiver>
        auto connect(Receiver &&r) && {
            return recv_from_operation<Receiver>{*this, (Receiver &&) r};
        }
    };
}

namespace g6::net {
    auto tag_invoke(
        tag_t<async_accept>,
        async_socket &socket) noexcept {
        return detail::accept_sender{socket.context_, socket.fd_.get()};
    }

    auto tag_invoke(
        tag_t<async_connect>,
        async_socket &socket,
        ip_endpoint &&endpoint) noexcept {
        return detail::connect_sender{socket.context_, socket.fd_.get(), std::forward<ip_endpoint>(endpoint)};
    }

    auto tag_invoke(
        tag_t<async_send>,
        async_socket &socket,
        span<const std::byte> buffer) noexcept {
        return detail::send_sender{socket.context_, socket.fd_.get(), buffer};
    }

    auto tag_invoke(
        tag_t<async_recv>,
        async_socket &socket,
        span<std::byte> buffer) noexcept {
        return detail::recv_sender{socket.context_, socket.fd_.get(), buffer};
    }

    auto tag_invoke(
        tag_t<async_send_to>,
        async_socket &socket,
        span<const std::byte> buffer,
        net::ip_endpoint &&endpoint) noexcept {
        return detail::send_to_sender{socket.context_, socket.fd_.get(), 0, buffer, std::forward<ip_endpoint>(endpoint)};
    }

    auto tag_invoke(
        tag_t<async_recv_from>,
        async_socket &socket,
        span<std::byte> buffer) noexcept {
        return detail::recv_from_sender{socket.context_, socket.fd_.get(), 0, buffer};
    }
}

namespace g6::io {
    net::async_socket tag_invoke(
        tag_t<net::open_socket>,
        auto scheduler,
        int domain, int type, int proto) {
        int result = socket(domain, type, proto);
        if (result < 0) {
            int errorCode = errno;
            throw_(std::system_error{errorCode, std::system_category()});
        }
        return net::async_socket{scheduler.get_context(), result};
    }
}

#endif // G6_NET_IMPL_ASYNC_SOCKET_HPP_
