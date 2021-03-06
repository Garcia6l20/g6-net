#pragma once

namespace g6::ssl {
    /** @brief Creates an SSL tcp server
     *
     * @param scheduler
     * @param certificate
     * @param pk
     * @return The created ssl::async_socket
     */
    ssl::async_socket tag_invoke(tag_t<net::open_socket>, auto scheduler, ssl::certificate &certificate,
                                 ssl::private_key &pk) {
        int result = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (result < 0) {
            int errorCode = errno;
            throw_(std::system_error{errorCode, std::system_category()});
        }

        return ssl::async_socket{scheduler.get_context(), result, ssl::async_socket::connection_mode::server,
                                 std::forward<ssl::certificate>(certificate), std::forward<ssl::private_key>(pk)};
    }

    struct detail::accept_sender : net::detail::accept_sender {

        using base = net::detail::accept_sender;
        accept_sender(async_socket& socket) : base{socket.context_, socket.fd_.get()} {}

        friend io::context;

        template<typename Receiver>
        struct accept_operation : io::context::completion_base {
            int result = -1;
            io::context &context_;
            int fd_;
            int64_t offset_;
            std::span<std::byte const> io_data_;
            Receiver receiver_;

            template<typename Receiver2>
            explicit accept_operation(const auto &sender, Receiver2 &&r)
                : context_(sender.context_),
                  fd_(sender.fd_),
                  offset_{sender.offset_},
                  io_data_{sender.io_data_},
                  receiver_((Receiver2 &&) r) {
            }

            auto get_io_data() noexcept {
                socklen_ = this->io_data_.size();
                return std::tuple{this->io_data_.data(), 0, reinterpret_cast<uint64_t>(&socklen_)};
            }

            void start() noexcept {
                if (!context_.is_running_on_io_thread()) {
                    this->execute_ = &accept_operation::on_schedule_complete;
                    context_.schedule_remote(this);
                } else {
                    start_io();
                }
            }

            void start_io() noexcept {
                assert(this->context_.is_running_on_io_thread());

                auto populateSqe = [this](io_uring_sqe &sqe) noexcept {
                  const auto [data, len, off] = this->get_impl_io_data();
                  io_uring_prep_rw(IORING_OP_ACCEPT, &sqe, this->fd_, data, len, off);
                  sqe.user_data = reinterpret_cast<std::uintptr_t>(this);
                  this->execute_ = &accept_operation::on_operation_complete;
                };

                if (!this->context_.try_submit_io(populateSqe)) {
                    this->execute_ = &accept_operation::on_schedule_complete;
                    this->context_.schedule_pending_io(this);
                }
            }
            auto get_result() noexcept {
                int fd = this->result_;
                return std::tuple{
                    ssl::async_socket(fd, this->context_),
                                  net::ip_endpoint::from_sockaddr(*reinterpret_cast<const sockaddr *>(this->io_data_.data()))};
            }
            static void on_operation_complete(accept_operation *op) noexcept {

            }

            socklen_t socklen_{};
        };

        // Chains send/receive operation during handcheck.
        template<
            template<typename...> class Variant,
            template<typename...> class Tuple>
        using next_types = Variant<Tuple<size_t>>;

        // Produces void result.
        template<
            template<typename...> class Variant,
            template<typename...> class Tuple>
        using value_types = Variant<Tuple<async_socket, net::ip_endpoint>>;

        template<template<typename...> class Variant>
        using error_types = Variant<std::error_code, std::exception_ptr>;

        template<typename Receiver>
        auto connect(Receiver &&r) && {
            return accept_operation<Receiver>{*this, (Receiver &&) r};
        }
    };
    struct detail::connect_sender {
        async_socket &socket_;
        net::ip_endpoint endpoint_;
    };
    struct detail::recv_sender {
        async_socket &socket_;
        span<std::byte> data_;
    };
    struct detail::send_sender {
        async_socket &socket_;
        span<std::byte const> data_;
    };

    detail::accept_sender tag_invoke(tag_t<net::async_accept>, async_socket &socket) { return {socket}; }
    detail::connect_sender tag_invoke(tag_t<net::async_connect>, async_socket &socket, net::ip_endpoint endpoint) {
        return {socket, endpoint};
    }
    detail::recv_sender tag_invoke(tag_t<net::async_recv>, async_socket &socket, span<std::byte> data) {
        return {socket, data};
    }
    detail::send_sender tag_invoke(tag_t<net::async_send>, async_socket &socket, span<std::byte const> data) {
        return {socket, data};
    }

}// namespace g6::ssl