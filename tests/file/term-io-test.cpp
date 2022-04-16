#include <catch2/catch.hpp>

#include <g6/io/context.hpp>

#include <g6/sync_wait.hpp>

#include <source_location>
#include <span>
#include <stop_token>


using namespace g6;
using namespace std::chrono_literals;
using namespace std::string_view_literals;

TEST_CASE("temio test", "[g6::io::files]") {
    io::context ctx{};
    std::stop_source stop{};
    sync_wait(
        [&]() -> task<> {
            size_t written =
                co_await async_write_some(ctx.cout, "hello from {} !!!\n", std::source_location::current().file_name());
            REQUIRE(written > 0);
            stop.request_stop();
        }(),
        async_exec(ctx, stop.get_token()));
}