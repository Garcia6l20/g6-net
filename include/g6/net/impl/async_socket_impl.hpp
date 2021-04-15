#pragma once

#include <g6/net/async_socket.hpp>
#include <unifex/exception.hpp>

namespace g6::net {
    namespace detail {
        class accept_sender
        {
            template<typename Receiver>
            struct operation : io::context::io_operation_base<IORING_OP_ACCEPT, Receiver, operation> {
                friend io::context;

                explicit operation(accept_sender &sender, Receiver &&r)
                    : io::context::io_operation_base<IORING_OP_ACCEPT, Receiver, operation>{sender, (Receiver &&) r} {}
                auto get_io_data() noexcept {
                    return std::tuple{reinterpret_cast<std::byte *>(&sockaddr_storage_), 0,
                                      reinterpret_cast<uint64_t>(&socklen_)};
                }
                auto get_result() noexcept {
                    return std::make_tuple(
                        async_socket{this->context_, this->result_},
                        net::ip_endpoint::from_sockaddr(*reinterpret_cast<const sockaddr *>(&sockaddr_storage_)));
                }
                socklen_t socklen_{sizeof(sockaddr_storage)};
                sockaddr_storage sockaddr_storage_{};
            };
            template<auto, typename, template<class> typename>
            friend class io::context::io_operation_base;

        public:
            // Produces number of bytes read.
            template<template<typename...> class Variant, template<typename...> class Tuple>
            using value_types = Variant<Tuple<std::tuple<async_socket, net::ip_endpoint>>>;

            // Note: Only case it might complete with exception_ptr is if the
            // receiver's set_value() exits with an exception.
            template<template<typename...> class Variant>
            using error_types = Variant<std::error_code, std::exception_ptr>;

            static constexpr bool sends_done = true;

            explicit accept_sender(io::context &context, int fd) noexcept : context_{context}, fd_{fd} {}

            template<typename Receiver>
            auto connect(Receiver &&r) && {
                return operation<Receiver>{*this, (Receiver &&) r};
            }

        private:
            io::context &context_;
            int fd_;
        };

        class connect_sender
        {
            template<typename Receiver>
            struct operation : io::context::io_operation_base<IORING_OP_CONNECT, Receiver, operation> {

                friend io::context;

                explicit operation(connect_sender &sender, Receiver &&r)
                    : io::context::io_operation_base<IORING_OP_CONNECT, Receiver, operation>{sender, (Receiver &&) r} {
                    addr_len_ = sender.endpoint_.to_sockaddr(sockaddr_storage_);
                }

                auto get_result() noexcept { return int(this->result_); }

                auto get_io_data() noexcept {
                    return std::tuple{reinterpret_cast<std::byte *>(&sockaddr_storage_), 0, addr_len_};
                }
                sockaddr_storage sockaddr_storage_{};
                size_t addr_len_;
            };
            template<auto, typename, template<class> typename>
            friend class io::context::io_operation_base;

        public:
            // Produces number of bytes read.
            template<template<typename...> class Variant, template<typename...> class Tuple>
            using value_types = Variant<Tuple<int>>;

            // Note: Only case it might complete with exception_ptr is if the
            // receiver's set_value() exits with an exception.
            template<template<typename...> class Variant>
            using error_types = Variant<std::error_code, std::exception_ptr>;

            static constexpr bool sends_done = true;

            explicit connect_sender(io::context &context, int fd, const net::ip_endpoint &endpoint) noexcept
                : context_{context}, fd_{fd}, endpoint_{endpoint} {}

            template<typename Receiver>
            auto connect(Receiver &&r) && {
                return operation<Receiver>{*this, (Receiver &&) r};
            }

        private:
            io::context &context_;
            int fd_;
            net::ip_endpoint endpoint_;
        };

        class recv_sender
        {
            template<typename Receiver>
            struct operation : io::context::io_operation_base<IORING_OP_RECV, Receiver, operation> {
                friend io::context;

                explicit operation(recv_sender &sender, Receiver &&r)
                    : io::context::io_operation_base<IORING_OP_RECV, Receiver, operation>{sender, (Receiver &&) r},
                      buffer_{sender.buffer_} {}
                auto get_io_data() noexcept { return std::tuple{buffer_.data(), buffer_.size(), 0}; }
                auto get_result() noexcept { return size_t(this->result_); }
                span<std::byte> buffer_;
            };
            template<auto, typename, template<class> typename>
            friend class io::context::io_operation_base;

        public:
            // Produces number of bytes read.
            template<template<typename...> class Variant, template<typename...> class Tuple>
            using value_types = Variant<Tuple<size_t>>;

            // Note: Only case it might complete with exception_ptr is if the
            // receiver's set_value() exits with an exception.
            template<template<typename...> class Variant>
            using error_types = Variant<std::error_code, std::exception_ptr>;

            static constexpr bool sends_done = true;

            explicit recv_sender(io::context &context, int fd, span<std::byte> buffer) noexcept
                : context_{context}, fd_{fd}, buffer_{buffer} {}

            template<typename Receiver>
            auto connect(Receiver &&r) && {
                return operation<Receiver>{*this, (Receiver &&) r};
            }

        private:
            io::context &context_;
            int fd_;
            span<std::byte> buffer_;
        };

        class recv_from_sender
        {
            template<typename Receiver>
            struct operation : io::context::io_operation_base<IORING_OP_RECVMSG, Receiver, operation> {
                friend io::context;

                explicit operation(recv_from_sender &sender, Receiver &&r)
                    : io::context::io_operation_base<IORING_OP_RECVMSG, Receiver, operation>{sender, (Receiver &&) r} {
                    iovec_.iov_base = const_cast<std::byte *>(sender.buffer_.data());
                    iovec_.iov_len = sender.buffer_.size();
                }
                auto get_io_data() noexcept { return std::tuple{&msghdr_, 1, 0}; }
                auto get_result() noexcept {
                    return std::make_tuple(
                        size_t(this->result_),
                        net::ip_endpoint::from_sockaddr(*reinterpret_cast<sockaddr *>(&sockaddr_storage_)));
                }
                sockaddr_storage sockaddr_storage_;
                iovec iovec_;
                msghdr msghdr_{&sockaddr_storage_, sizeof(sockaddr_storage_), &iovec_, 1};
            };
            template<auto, typename, template<class> typename>
            friend class io::context::io_operation_base;

        public:
            // Produces number of bytes read.
            template<template<typename...> class Variant, template<typename...> class Tuple>
            using value_types = Variant<Tuple<size_t, net::ip_endpoint>>;

            // Note: Only case it might complete with exception_ptr is if the
            // receiver's set_value() exits with an exception.
            template<template<typename...> class Variant>
            using error_types = Variant<std::error_code, std::exception_ptr>;

            static constexpr bool sends_done = true;

            explicit recv_from_sender(io::context &context, int fd, span<std::byte> buffer) noexcept
                : context_{context}, fd_{fd}, buffer_{buffer} {}

            template<typename Receiver>
            auto connect(Receiver &&r) && {
                return operation<Receiver>{*this, (Receiver &&) r};
            }

        private:
            io::context &context_;
            int fd_;
            span<const std::byte> buffer_;
        };

        class send_sender
        {
            template<typename Receiver>
            struct operation : io::context::io_operation_base<IORING_OP_SEND, Receiver, operation> {
                friend io::context;

                explicit operation(send_sender &sender, Receiver &&r)
                    : io::context::io_operation_base<IORING_OP_SEND, Receiver, operation>{sender, (Receiver &&) r},
                      buffer_{sender.buffer_} {}
                auto get_io_data() noexcept { return std::tuple{buffer_.data(), buffer_.size(), 0}; }
                auto get_result() noexcept { return size_t(this->result_); }
                span<const std::byte> buffer_;
            };
            template<auto, typename, template<class> typename>
            friend class io::context::io_operation_base;

        public:
            // Produces number of bytes read.
            template<template<typename...> class Variant, template<typename...> class Tuple>
            using value_types = Variant<Tuple<size_t>>;

            // Note: Only case it might complete with exception_ptr is if the
            // receiver's set_value() exits with an exception.
            template<template<typename...> class Variant>
            using error_types = Variant<std::error_code, std::exception_ptr>;

            static constexpr bool sends_done = true;

            explicit send_sender(io::context &context, int fd, span<const std::byte> buffer) noexcept
                : context_{context}, fd_{fd}, buffer_{buffer} {}

            template<typename Receiver>
            auto connect(Receiver &&r) && {
                return operation<Receiver>{*this, (Receiver &&) r};
            }

        private:
            io::context &context_;
            int fd_;
            span<const std::byte> buffer_;
        };

        class send_to_sender
        {
            template<typename Receiver>
            struct operation : io::context::io_operation_base<IORING_OP_SENDMSG, Receiver, operation> {
                friend io::context;

                explicit operation(send_to_sender &sender, Receiver &&r)
                    : io::context::io_operation_base<IORING_OP_SENDMSG, Receiver, operation>{sender, (Receiver &&) r} {
                    iovec_.iov_base = const_cast<std::byte *>(sender.buffer_.data());
                    iovec_.iov_len = sender.buffer_.size();
                    msghdr_.msg_namelen = sender.to_.to_sockaddr(sockaddr_storage_);
                }
                auto get_io_data() noexcept { return std::tuple{&msghdr_, 1, 0}; }
                auto get_result() noexcept { return size_t(this->result_); }
                sockaddr_storage sockaddr_storage_;
                iovec iovec_;
                msghdr msghdr_{&sockaddr_storage_, sizeof(sockaddr_storage_), &iovec_, 1};
            };
            template<auto, typename, template<class> typename>
            friend class io::context::io_operation_base;

        public:
            // Produces number of bytes read.
            template<template<typename...> class Variant, template<typename...> class Tuple>
            using value_types = Variant<Tuple<size_t>>;

            // Note: Only case it might complete with exception_ptr is if the
            // receiver's set_value() exits with an exception.
            template<template<typename...> class Variant>
            using error_types = Variant<std::error_code, std::exception_ptr>;

            static constexpr bool sends_done = true;

            explicit send_to_sender(io::context &context, int fd, const net::ip_endpoint &endpoint,
                                    span<const std::byte> buffer) noexcept
                : context_{context}, fd_{fd}, buffer_{buffer}, to_{endpoint} {}

            template<typename Receiver>
            auto connect(Receiver &&r) && {
                return operation<Receiver>{*this, (Receiver &&) r};
            }

        private:
            io::context &context_;
            int fd_;
            span<const std::byte> buffer_;
            net::ip_endpoint to_;
        };

    }// namespace detail

    auto tag_invoke(tag_t<async_accept>, async_socket &socket) noexcept {
        return detail::accept_sender{socket.context_, socket.fd_.get()};
    }

    auto tag_invoke(tag_t<async_connect>, async_socket &socket, const ip_endpoint &endpoint) noexcept {
        return detail::connect_sender{socket.context_, socket.fd_.get(), endpoint};
    }

    auto tag_invoke(tag_t<async_connect>, auto &context, int fd, ip_endpoint const &endpoint) noexcept {
        return detail::connect_sender{context, fd, endpoint};
    }

    auto tag_invoke(tag_t<async_send>, async_socket &socket, span<const std::byte> buffer) noexcept {
        return detail::send_sender{socket.context_, socket.fd_.get(), buffer};
    }

    auto tag_invoke(tag_t<async_recv>, async_socket &socket, span<std::byte> buffer) noexcept {
        return detail::recv_sender{socket.context_, socket.fd_.get(), buffer};
    }

    auto tag_invoke(tag_t<async_send_to>, async_socket &socket, span<const std::byte> buffer,
                    net::ip_endpoint const &endpoint) noexcept {
        return detail::send_to_sender{socket.context_, socket.fd_.get(), endpoint, buffer};
    }

    auto tag_invoke(tag_t<async_recv_from>, async_socket &socket, span<std::byte> buffer) noexcept {
        return detail::recv_from_sender{socket.context_, socket.fd_.get(), buffer};
    }
}// namespace g6::net

namespace g6::io {
    net::async_socket tag_invoke(tag_t<net::open_socket>, auto &ctx, int domain, int type, int proto) {
        int result = socket(domain, type, proto);
        if (result < 0) {
            int errorCode = errno;
            throw_(std::system_error{errorCode, std::system_category()});
        }
        return net::async_socket{ctx, result};
    }

    template<class IOContext2>
    auto tag_invoke(unifex::tag_t<net::open_socket>, IOContext2 &ctx, net::detail::tags::tcp_server const &,
                    const net::ip_endpoint &endpoint) {
        auto sock = net::open_socket(ctx, AF_INET, SOCK_STREAM);
        sock.bind(endpoint);
        sock.listen();
        return sock;
    }

    template<class IOContext2>
    auto tag_invoke(unifex::tag_t<net::open_socket>, IOContext2 &ctx, net::detail::tags::tcp_client const &) {
        return net::open_socket(ctx, AF_INET, SOCK_STREAM);
    }

}// namespace g6::net
