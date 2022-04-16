#pragma once

#include <g6/io_context.hpp>

#include <g6/io/config.hpp>
#include <g6/io/io_cpo.hpp>

#include <g6/cpo/file.hpp>

#include <g6/net/ip_endpoint.hpp>
#include <g6/net/net_cpo.hpp>
#include <g6/net/socket_protocols.hpp>

#include <fmt/format.h>
#include <string_view>
#include <unistd.h>

#include <span>

namespace g6::io {

#if G6_OS_WINDOWS
    std::tuple<SOCKET, bool> create_socket(net::socket_protocol type, HANDLE ioCompletionPort);
#endif

    class context : public io_context {

#if G6_OS_WINDOWS
        static inline bool winsock_initialized = false;
        friend void ensure_winsock_initialized();
#endif

        template<auto FileNo>
        class term_io : private file {
            static const auto fileno_ = FileNo;
            context &ctx_;
            friend class context;
            term_io(context &ctx) noexcept : file{ctx, FileNo}, ctx_{ctx} { dont_close(); }

            template<size_t extent>
            friend auto tag_invoke(tag_t<async_read_some>, term_io<FileNo> &io, std::span<std::byte, extent> buffer) {
                return async_read_some(static_cast<file &>(io), buffer);
            }

            template<size_t extent>
            friend auto tag_invoke(tag_t<async_write_some>, term_io<FileNo> &io,
                                   std::span<std::byte const, extent> buffer) {
                return async_write_some(static_cast<file &>(io), buffer);
            }

            template<size_t N, typename... Args>
            friend task<size_t> tag_invoke(tag_t<async_write_some>, term_io<FileNo> &io, const char (&format_)[N],
                                           Args &&...args) {
                auto buffer = fmt::vformat(std::string_view{format_}, fmt::make_format_args(args...));
                co_return co_await async_write_some(io, std::as_bytes(std::span{buffer.data(), buffer.size()}));
            }
        };

    public:
        friend auto tag_invoke(tag_t<net::open_socket>, io::context &ctx, net::socket_protocol socket_protocol);

        term_io<STDIN_FILENO> cin{*this};
        term_io<STDOUT_FILENO> cout{*this};
        term_io<STDERR_FILENO> cerr{*this};
    };

}// namespace g6::io

#include <g6/io/impl/context_impl.hpp>
