#ifndef G6_NET_IMPL_ASYNC_SOCKET_HPP_
#define G6_NET_IMPL_ASYNC_SOCKET_HPP_

#include <g6/net/async_socket.hpp>

namespace g6::net {
    namespace detail {
        struct accept_sender : io::context::base_sender {
            accept_sender(io::context &context, int fd) noexcept : io::context::base_sender{context, fd} {}

            template<typename Receiver>
            struct operation
                : io::context::base_operation<io::detail::io_operation_id::accept, Receiver, operation<Receiver>> {
                using base =
                    io::context::base_operation<io::detail::io_operation_id::accept, Receiver, operation<Receiver>>;
                using base::base;
                auto get_io_data() noexcept {
                    socklen_ = sizeof(sockaddr_storage_);
                    return std::tuple{reinterpret_cast<std::byte *>(&sockaddr_storage_), 0,
                                      reinterpret_cast<uint64_t>(&socklen_)};
                }
                auto get_result() noexcept {
                    int fd = this->result_;
                    return std::tuple{
                        async_socket(this->context_, fd),
                        ip_endpoint::from_sockaddr(*reinterpret_cast<const sockaddr *>(&sockaddr_storage_))};
                }
                socklen_t socklen_{};
                sockaddr_storage sockaddr_storage_{};
            };

            // Produces void result.
            template<template<typename...> class Variant, template<typename...> class Tuple>
            using value_types = Variant<Tuple<async_socket, ip_endpoint>>;

            template<template<typename...> class Variant>
            using error_types = Variant<std::error_code, std::exception_ptr>;

            template<typename Receiver>
            auto connect(Receiver &&r) && {
                return operation<Receiver>{*this, (Receiver &&) r};
            }
        };

        struct connect_sender : io::context::base_sender {
            connect_sender(io::context &context, int fd, ip_endpoint &&endpoint) noexcept
                : io::context::base_sender{context, fd}, endpoint_{std::forward<ip_endpoint>(endpoint)} {}

            template<typename Receiver>
            struct operation
                : io::context::base_operation<io::detail::io_operation_id::connect, Receiver, operation<Receiver>> {
                using base =
                    io::context::base_operation<io::detail::io_operation_id::connect, Receiver, operation<Receiver>>;
                using base::base;
                template<typename Receiver2>
                explicit operation(const auto &sender, Receiver2 &&r, ip_endpoint &&endpoint)
                    : base{sender, std::forward<Receiver2>(r)} {
                    addr_len_ = endpoint.to_sockaddr(sockaddr_storage_);
                }
                auto get_io_data() noexcept {
                    return std::tuple{reinterpret_cast<std::byte *>(&sockaddr_storage_), 0, addr_len_};
                }
                sockaddr_storage sockaddr_storage_{};
                size_t addr_len_;
            };

            // Produces int result.
            template<template<typename...> class Variant, template<typename...> class Tuple>
            using value_types = Variant<Tuple<int>>;

            template<template<typename...> class Variant>
            using error_types = Variant<std::error_code, std::exception_ptr>;

            template<typename Receiver>
            auto connect(Receiver &&r) && {
                return operation<Receiver>{*this, (Receiver &&) r, std::move(endpoint_)};
            }

            ip_endpoint endpoint_{};
            std::span<std::byte const> io_data_{};
            static constexpr int64_t offset_{0};
        };

        template<io::detail::io_operation_id io_op, typename Receiver, typename DataT = std::byte>
        struct io_data_operation
            : io::context::base_operation<io_op, Receiver, io_data_operation<io_op, Receiver, DataT>> {
            using base = io::context::base_operation<io_op, Receiver, io_data_operation<io_op, Receiver, DataT>>;

            template<typename Receiver2>
            explicit io_data_operation(const auto &sender, Receiver2 &&r)
                : base{sender, std::forward<Receiver2>(r)}, io_data_{sender.io_data_} {}
            auto get_io_data() noexcept { return std::tuple{io_data_.data(), io_data_.size_bytes(), 0}; }
            std::span<DataT> io_data_{};
        };

        struct send_sender : io::context::base_sender {
            send_sender(io::context &context, int fd, std::span<std::byte const> buffer) noexcept
                : io::context::base_sender{context, fd}, io_data_{buffer} {}

            template<typename Receiver>
            auto connect(Receiver &&r) && {
                return detail::io_data_operation<io::detail::io_operation_id::send, Receiver, std::byte const>{
                    *this, (Receiver &&) r};
            }

            std::span<std::byte const> io_data_{};
        };

        struct recv_sender : io::context::base_sender {
            recv_sender(io::context &context, int fd, std::span<std::byte> buffer) noexcept
                : io::context::base_sender{context, fd}, io_data_{buffer} {}

            template<typename Receiver>
            auto connect(Receiver &&r) && {
                return detail::io_data_operation<io::detail::io_operation_id::recv, Receiver>{*this, (Receiver &&) r};
            }

            std::span<std::byte> io_data_{};
        };

        struct send_to_sender : io::context::base_sender {

            template<typename Receiver>
            struct operation
                : io::context::base_operation<io::detail::io_operation_id::sendmsg, Receiver, operation<Receiver>> {
                using base =
                    io::context::base_operation<io::detail::io_operation_id::sendmsg, Receiver, operation<Receiver>>;

                template<typename Receiver2>
                explicit operation(auto &sender, Receiver2 &&r)
                    : base{sender, std::forward<Receiver2>(r)}, msghdr_{sender.msghdr_} {
                    std::memcpy(&msghdr_, &sender.msghdr_, sizeof(msghdr_));
                }
                auto get_io_data() noexcept { return std::tuple{&msghdr_, 1, 0}; }
                msghdr &msghdr_;
            };

            explicit send_to_sender(io::context &ctx, int fd, int64_t offset, span<const std::byte> buffer,
                                    std::optional<net::ip_endpoint> endpoint = {})
                : io::context::base_sender{ctx, fd}, offset_{offset}, iovec_{const_cast<std::byte *>(buffer.data()),
                                                                             buffer.size()} {
                if (endpoint) msghdr_.msg_namelen = endpoint->to_sockaddr(sockaddr_storage_);
            }

            template<typename Receiver>
            auto connect(Receiver &&r) && {
                return operation<Receiver>{*this, (Receiver &&) r};
            }

            int64_t offset_ = 0;
            sockaddr_storage sockaddr_storage_{};
            iovec iovec_;
            msghdr msghdr_{&sockaddr_storage_, sizeof(sockaddr_storage_), &iovec_, 1};
            const std::span<std::byte const> io_data_{
                std::as_bytes(std::span{reinterpret_cast<std::byte *>(&msghdr_), 1})};
        };

        template<typename Receiver>
        struct recv_from_operation : io::context::base_operation<io::detail::io_operation_id::recvmsg, Receiver, recv_from_operation<Receiver>> {
            using base = io::context::base_operation<io::detail::io_operation_id::recvmsg, Receiver, recv_from_operation<Receiver>>;
            using base::base;

            explicit recv_from_operation(auto &sender, auto &&r)
                : base{sender, std::forward<decltype(r)>(r)}, msghdr_{sender.msghdr_} {
                std::memcpy(&msghdr_, &sender.msghdr_, sizeof(msghdr_));
            }

            auto get_result() noexcept {
                return std::make_tuple(
                    size_t(this->result_),
                    ip_endpoint::from_sockaddr(*reinterpret_cast<const sockaddr *>(msghdr_.msg_name)));
            }

            auto get_io_data() noexcept { return std::tuple{&msghdr_, 1, 0}; }

            msghdr &msghdr_;
        };

        struct recv_from_sender : io::context::base_sender {

            // Produces number of bytes read.
            template<template<typename...> class Variant, template<typename...> class Tuple>
            using value_types = Variant<Tuple<size_t, ip_endpoint>>;

            explicit recv_from_sender(io::context &ctx, int fd, int64_t offset, span<std::byte> buffer)
                : io::context::base_sender{ctx, fd}, offset_{offset}, iovec_{const_cast<std::byte *>(buffer.data()),
                                                                             buffer.size()} {}

            template<typename Receiver>
            auto connect(Receiver &&r) && {
                return recv_from_operation<Receiver>{*this, (Receiver &&) r};
            }

            int64_t offset_ = 0;
            sockaddr_storage sockaddr_storage_{};
            iovec iovec_;
            msghdr msghdr_{&sockaddr_storage_, sizeof(sockaddr_storage_), &iovec_, 1};
            const std::span<std::byte const> io_data_{
                std::as_bytes(std::span{reinterpret_cast<std::byte *>(&msghdr_), 1})};
        };
    }// namespace detail

    auto tag_invoke(tag_t<async_accept>, async_socket &socket) noexcept {
        return detail::accept_sender{socket.context_, socket.fd_.get()};
    }

    auto tag_invoke(tag_t<async_connect>, async_socket &socket, ip_endpoint &&endpoint) noexcept {
        return detail::connect_sender{socket.context_, socket.fd_.get(), std::forward<ip_endpoint>(endpoint)};
    }

    auto tag_invoke(tag_t<async_connect>, auto &context, int fd, ip_endpoint &&endpoint) noexcept {
        return detail::connect_sender{context, fd, std::forward<ip_endpoint>(endpoint)};
    }

    auto tag_invoke(tag_t<async_send>, async_socket &socket, span<const std::byte> buffer) noexcept {
        return detail::send_sender{socket.context_, socket.fd_.get(), buffer};
    }

    auto tag_invoke(tag_t<async_recv>, async_socket &socket, span<std::byte> buffer) noexcept {
        return detail::recv_sender{socket.context_, socket.fd_.get(), buffer};
    }

    auto tag_invoke(tag_t<async_send_to>, async_socket &socket, span<const std::byte> buffer,
                    net::ip_endpoint &&endpoint) noexcept {
        return detail::send_to_sender{socket.context_, socket.fd_.get(), 0, buffer,
                                      std::forward<ip_endpoint>(endpoint)};
    }

    auto tag_invoke(tag_t<async_recv_from>, async_socket &socket, span<std::byte> buffer) noexcept {
        return detail::recv_from_sender{socket.context_, socket.fd_.get(), 0, buffer};
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
}// namespace g6::io

#endif// G6_NET_IMPL_ASYNC_SOCKET_HPP_
