#include <catch2/catch.hpp>

#include <unifex/sync_wait.hpp>
#include <unifex/task.hpp>
#include <unifex/transform.hpp>
#include <unifex/when_all.hpp>

#include <g6/io/context.hpp>

#include <fmt/format.h>

using namespace g6;
using namespace std::chrono_literals;

TEST_CASE("file test", "[g6::io::files]") {
    io::context ctx{};
    inplace_stop_source stop_source{};

    sync_wait(when_all(
        [&]() -> task<void> {
          scope_guard _ = [&]() noexcept {
            stop_source.request_stop();
          };
          auto ro_file = open_file_read_only(ctx.get_scheduler(), __FILE__);
          std::array<char, 1024> data{};
          size_t bytes = co_await async_read_some_at(ro_file, 0, as_writable_bytes(span{data}));
          fmt::print("read: {}\n", std::string_view{data.data(), bytes});
        }(),
        [&]() -> task<void> {
          ctx.run(stop_source.get_token());
          co_return;
        }()));
}
