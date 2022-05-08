#pragma once

// must be first, I dont realy know why :/
#include <g6/format.hpp>
#include <g6/from_string.hpp>

#include <g6/io_context.hpp>
#include <g6/task.hpp>

#include <g6/io/io_cpo.hpp>

#include <g6/cpo/file.hpp>

#include <g6/net/ip_endpoint.hpp>
#include <g6/net/net_cpo.hpp>
#include <g6/net/socket_protocols.hpp>

#include <fmt/format.h>
#include <string_view>


#if G6_OS_LINUX
#include <unistd.h>
#endif

#include <span>

namespace g6::io {

    class context;
    class term_io;

    template<size_t extent>
    auto tag_invoke(tag_t<async_read_some>, term_io &, std::span<std::byte, extent>);

    template<size_t extent>
    auto tag_invoke(tag_t<async_write_some>, term_io &, std::span<std::byte, extent>);

    template<size_t N, typename... Args>
    task<size_t> tag_invoke(tag_t<async_write_some>, term_io &, const char (&)[N], Args &&...);

    class term_io {
        g6::io::context &ctx_;
        g6::file file_;

    public:
        term_io(context &ctx, auto file_no) noexcept : file_{ctx, file_no}, ctx_{ctx} { file_.dont_close(); }

        template<size_t extent>
        friend auto tag_invoke(tag_t<async_read_some>, term_io &, std::span<std::byte, extent>);

        template<size_t extent>
        friend auto tag_invoke(tag_t<async_write_some>, term_io &, std::span<std::byte const, extent>);

        template<size_t N, typename... Args>
        friend task<size_t> tag_invoke(tag_t<async_write_some>, term_io &, const char (&)[N], Args &&...);
    };

#if G6_OS_WINDOWS
    std::tuple<SOCKET, bool> create_socket(net::socket_protocol type, HANDLE ioCompletionPort);
#endif

    class context : public io_context {

#if G6_OS_WINDOWS
        static inline bool winsock_initialized = false;
        friend void ensure_winsock_initialized();
#endif


    public:
        friend auto tag_invoke(tag_t<net::open_socket>, io::context &ctx, net::socket_protocol socket_protocol);

#if G6_OS_WINDOWS
        term_io cin{*this, GetStdHandle(STD_INPUT_HANDLE)};
        term_io cout{*this, GetStdHandle(STD_OUTPUT_HANDLE)};
        term_io cerr{*this, GetStdHandle(STD_ERROR_HANDLE)};
#else
        term_io cin{*this, STDIN_FILENO};
        term_io cout{*this, STDOUT_FILENO};
        term_io cerr{*this, STDERR_FILENO};
#endif
    };

    template<size_t extent>
    auto tag_invoke(tag_t<async_read_some>, term_io &io, std::span<std::byte, extent> buffer) {
        return async_read_some(io.file_, buffer);
    }

    template<size_t extent>
    auto tag_invoke(tag_t<async_write_some>, term_io &io, std::span<std::byte const, extent> buffer) {
        return async_write_some(io.file_, buffer);
    }

    template<size_t N, typename... Args>
    task<size_t> tag_invoke(tag_t<async_write_some>, term_io &io, const char (&format_)[N], Args &&...args) {
        auto buffer = fmt::vformat(std::string_view{format_}, fmt::make_format_args(args...));
        co_return co_await async_write_some(io.file_, std::as_bytes(std::span{buffer.data(), buffer.size()}));
    }

}// namespace g6::io

#include <g6/io/impl/context_impl.hpp>
