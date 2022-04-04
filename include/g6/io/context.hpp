#ifndef G6_IO_CONTEXT_HPP_
#define G6_IO_CONTEXT_HPP_

#include <g6/io_context.hpp>

#include <g6/io/config.hpp>
#include <g6/io/io_cpo.hpp>

#include <spdlog/spdlog.h>

namespace g6::io {

    class context : public io_context {
        // template<auto FileNo>
        // class term_io_ {
        //     static const auto fileno_ = FileNo;
        //     context &ctx_;
        //     friend class context;
        //     term_io_(context &ctx) noexcept : ctx_{ctx} {}

        //     friend auto tag_invoke(tag<async_read>, term_io_<FileNo> &io, span<std::byte> buffer) {
        //         return read_sender{io.ctx_, io.fileno_, 0, buffer};
        //     }

        //     friend auto tag_invoke(tag<async_write>, term_io_<FileNo> &io, span<std::byte const> buffer) {
        //         return write_sender{io.ctx_, io.fileno_, 0, buffer};
        //     }

        //     friend task<size_t> tag_invoke(tag<async_write>, term_io_<FileNo> &io, std::string_view fmt,
        //                                    auto &&...args) {
        //         auto buffer = fmt::format(fmt, std::forward<decltype(args)>(args)...);
        //         co_return co_await async_write(io, as_bytes(span{buffer.data(), buffer.size()}));
        //     }
        // };

    public:
    };

}// namespace g6::io

#endif// G6_IO_CONTEXT_HPP_
