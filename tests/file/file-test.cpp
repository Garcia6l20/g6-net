#include <catch2/catch.hpp>

#include <g6/coro/sync_wait.hpp>
#include <g6/io/context.hpp>
#include <g6/scope_guard.hpp>


#include <fmt/format.h>

using namespace g6;
using namespace std::chrono_literals;


TEST_CASE("g6::io::context: file test", "[g6][io][file]") {
    io::context ctx{};
    std::stop_source stop_source{};

    auto [read_bytes, _] = sync_wait(
        [&]() -> task<size_t> {
            scope_guard _ = [&]() noexcept { stop_source.request_stop(); };
            auto ro_file = open_file(ctx, __FILE__, open_file_mode::read | open_file_mode::existing);
            std::array<char, 1024> data{};
            size_t bytes =
                co_await async_read_some(ro_file, std::as_writable_bytes(std::span{data.data(), data.size()}));
            co_return bytes;
        }(),
        async_exec(ctx, stop_source.get_token()));
    REQUIRE(read_bytes != 0);
}
