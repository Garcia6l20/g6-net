#include <g6/io/context.hpp>
#include <g6/net/net_concepts.hpp>

namespace g6::net {
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

        friend auto tag_invoke(
            tag_t<async_send>,
            async_socket &socket,
            span<const std::byte> buffer) noexcept {
            return io_uring_context::write_sender{socket.context_, socket.fd_.get(), 0, buffer};
        }

        friend auto tag_invoke(
            tag_t<async_recv>,
            async_socket &socket,
            span<std::byte> buffer) noexcept {
            return io_uring_context::read_sender{socket.context_, socket.fd_.get(), 0, buffer};
        }

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
            const void *io_data_{&msghdr_};
        };

        friend auto tag_invoke(
            tag_t<async_send_to>,
            async_socket &socket,
            span<const std::byte> buffer,
            net::ip_endpoint &&endpoint) noexcept {
            return msg_sender<IORING_OP_SENDMSG>{socket.context_, socket.fd_.get(), 0, buffer, std::forward<ip_endpoint>(endpoint)};
        }

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

        friend auto tag_invoke(
            tag_t<async_recv_from>,
            async_socket &socket,
            span<std::byte> buffer) noexcept {
            return recv_from_sender{socket.context_, socket.fd_.get(), 0, buffer};
        }


    private:
        //    friend io_uring_context::scheduler;
        io::context &context_;
        safe_file_descriptor fd_;
    };

}// namespace g6::net

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
}// namespace g6::io
