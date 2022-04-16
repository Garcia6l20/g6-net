#pragma once

#include <g6/io_context.hpp>

#include <g6/io/config.hpp>
#include <g6/io/io_cpo.hpp>

#include <g6/net/ip_endpoint.hpp>
#include <g6/net/net_cpo.hpp>
#include <g6/net/socket_protocols.hpp>

namespace g6::io {

#if G6_OS_WINDOWS
    std::tuple<SOCKET, bool> create_socket(net::socket_protocol type, HANDLE ioCompletionPort);
#endif

    class context : public io_context {

#if G6_OS_WINDOWS
        static inline bool winsock_initialized = false;
        friend void ensure_winsock_initialized();
#endif

        // template<auto FileNo>
        // class term_io_ {
        //     static const auto fileno_ = FileNo;
        //     context &ctx_;
        //     friend class context;
        //     term_io_(context &ctx) noexcept : ctx_{ctx} {}

        //     friend auto tag_invoke(tag_t<async_read>, term_io_<FileNo> &io, span<std::byte> buffer) {
        //         return read_sender{io.ctx_, io.fileno_, 0, buffer};
        //     }

        //     friend auto tag_invoke(tag_t<async_write>, term_io_<FileNo> &io, span<std::byte const> buffer) {
        //         return write_sender{io.ctx_, io.fileno_, 0, buffer};
        //     }

        //     friend task<size_t> tag_invoke(tag_t<async_write>, term_io_<FileNo> &io, std::string_view fmt,
        //                                    auto &&...args) {
        //         auto buffer = fmt::format(fmt, std::forward<decltype(args)>(args)...);
        //         co_return co_await async_write(io, as_bytes(span{buffer.data(), buffer.size()}));
        //     }
        // };

    public:
        friend auto tag_invoke(tag_t<net::open_socket>, io::context &ctx, net::socket_protocol socket_protocol);
    };

}// namespace g6::io

#include <g6/io/impl/context_impl.hpp>
