#include <catch2/catch.hpp>

#include <g6/io/context.hpp>
#include <g6/spawner.hpp>


#include <fmt/format.h>

using namespace g6;
using namespace std::chrono_literals;


TEST_CASE("file test", "[g6::io::files]") {
    io::context ctx{};
    std::stop_source stop_source{};

    spawner{[&]() -> task<void> {
                scope_guard _ = [&]() noexcept { stop_source.request_stop(); };
                auto ro_file = open_file(ctx, __FILE__, open_file_mode::read | open_file_mode::existing);
                std::array<char, 1024> data{};
                size_t bytes = co_await async_read_some_at(
                    ro_file, std::as_writable_bytes(std::span{data.data(), data.size()}), 0);
                fmt::print("read: {}\n", std::string_view{data.data(), bytes});
            }(),
            async_exec(ctx)}
        .sync_wait();
}
