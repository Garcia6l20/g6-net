#include <catch2/catch.hpp>

#include <g6/io/async_event.hpp>

#include <unifex/sync_wait.hpp>
#include <unifex/task.hpp>
#include <unifex/when_all.hpp>

#include <unifex/async_manual_reset_event.hpp>
#include <unifex/async_scope.hpp>
#include <unifex/just.hpp>
#include <unifex/single_thread_context.hpp>
#include <unifex/transform.hpp>

using namespace g6;
using namespace unifex;

TEST_CASE("get universal response", "[g6::io::async_event]") {
    async_event<int> universal_response_event{};
    SECTION("unique receiver") {
        sync_wait(when_all(
            [&]() -> task<void> {
                auto val = co_await universal_response_event;
                REQUIRE(val == 42);
            }(),
            [&]() -> task<void> {
                universal_response_event.publish(42);
                co_return;
            }()));
    }
    SECTION("multi receivers") {
        sync_wait(when_all(
            [&]() -> task<void> {
                auto val = co_await universal_response_event;
                REQUIRE(val == 42);
            }(),
            [&]() -> task<void> {
                auto val = co_await universal_response_event;
                REQUIRE(val == 42);
            }(),
            [&]() -> task<void> {
                universal_response_event.publish(42);
                co_return;
            }()));
    }
    SECTION("simple sequence - multi receivers") {
        sync_wait(when_all(
            [&]() -> task<void> {
                auto val = co_await universal_response_event;
                REQUIRE(val == 42);
                val = co_await universal_response_event;
                REQUIRE(val == 43);
            }(),
            [&]() -> task<void> {
                universal_response_event.publish(42);
                universal_response_event.publish(43);
                co_return;
            }()));
    }
    SECTION("ping pong") {
        single_thread_context ctx{};
        auto sched = ctx.get_scheduler();
        async_event<int> ping_pong{};
        sync_wait(when_all(
            [&]() -> task<void> {
                co_await schedule(sched);
                auto val = co_await ping_pong;
                REQUIRE(val == 42);
                co_await schedule(sched);// re-schedule
                ping_pong.publish(43);
            }(),
            [&]() -> task<void> {
                co_await schedule(sched);
                ping_pong.publish(42);// return only when awaiters are notified
                auto val = co_await ping_pong;
                REQUIRE(val == 43);
            }()));
    }
    SECTION("set from multiple coroutine") {
        async_event<int> ping_pong{};
        sync_wait(when_all(
            [&]() -> task<void> {
                auto val = co_await ping_pong;
                REQUIRE(val == 42);
                val = co_await ping_pong;
                REQUIRE(val == 43);
            }(),
            [&]() -> task<void> {
                ping_pong << 42;
                co_return;
            }(),
            [&]() -> task<void> {
                ping_pong << 43;
                co_return;
            }()));
    }
}

TEST_CASE("simple sequence - unique receiver", "[g6::io::async_event]") {
    async_event<int> event{};
    sync_wait(when_all(
        [&]() -> task<void> {
            auto val = co_await event;
            REQUIRE(val == 42);
            val = co_await event;
            REQUIRE(val == 43);
        }(),
        [&]() -> task<void> {
            event << 42 << 43;
            co_return;
        }()));
}

TEST_CASE("get universal response from other thread", "[g6::io::async_event]") {
    single_thread_context ctx{};
    single_thread_context ctx2{};
    async_event<int> universal_response_event{};
    SECTION("unique receiver") {
        sync_wait(when_all(
            [&]() -> task<void> {
                co_await schedule(ctx.get_scheduler());
                auto val = co_await universal_response_event;
                REQUIRE(val == 42);
            }(),
            [&]() -> task<void> {
                co_await schedule(ctx2.get_scheduler());
                auto val = co_await universal_response_event;
                REQUIRE(val == 42);
            }(),
            [&]() -> task<void> {
                co_await when_all(schedule(ctx.get_scheduler()), schedule(ctx2.get_scheduler()));
                universal_response_event << 42;
                co_return;
            }()));
    }
}

TEST_CASE("get universal response - multi threaded", "[g6::io::async_event]") {
    single_thread_context ctx{};
    single_thread_context ctx2{};
    async_event<int> event{};
    async_event<bool> ready[3];
    auto wait_event = [](auto &event) -> task<void> { co_await event; };
    sync_wait(when_all(
        [&]() -> task<void> {
            // wait listeners ready
            co_await when_all(wait_event(ready[0]), wait_event(ready[1]), wait_event(ready[2]));
            event << 42;
        }(),
        [&]() -> task<void> {
            co_await schedule(ctx.get_scheduler());
            co_await when_all(
                [&]() -> task<void> {
                    auto val = co_await event;
                    REQUIRE(val == 42);
                }(),
                [&]() -> task<void> {
                    ready[0] << true;
                    co_return;
                }());
        }(),
        [&]() -> task<void> {
            co_await schedule(ctx.get_scheduler());
            co_await when_all(
                [&]() -> task<void> {
                    auto val = co_await event;
                    REQUIRE(val == 42);
                }(),
                [&]() -> task<void> {
                    ready[1] << true;
                    co_return;
                }());
        }(),
        [&]() -> task<void> {
            co_await schedule(ctx2.get_scheduler());
            co_await when_all(
                [&]() -> task<void> {
                    auto val = co_await event;
                    REQUIRE(val == 42);
                }(),
                [&]() -> task<void> {
                    ready[2] << true;
                    co_return;
                }());
        }()));
}

TEST_CASE("references", "[g6::io::async_event]") {
    int value = 42;
    async_event<int &> event{};
    SECTION("unique receiver") {
        sync_wait(when_all(
            [&]() -> task<void> {
                auto &val = co_await event;
                REQUIRE(val == 42);
                REQUIRE(&val == &value);
            }(),
            [&]() -> task<void> {
                event.publish(value);
                co_return;
            }()));
    }
}
