#include <catch2/catch.hpp>

#include <fmt/format.h>

#include <g6/io/context.hpp>
#include <g6/net/async_socket.hpp>
#include <g6/net/ip_endpoint.hpp>
#include <g6/utils/scope_guard.hpp>

#include <g6/spawner.hpp>

using namespace g6;

TEST_CASE("udp tx/rx test", "[g6::net::udp]") {
    io::context ctx{};
    std::stop_source stop_source{};
    using namespace std::chrono_literals;

    auto [rx_bytes, tx_bytes, _] =
        spawner{[&]() -> task<size_t> {
                    scope_guard _ = [&]() noexcept { stop_source.request_stop(); };
                    auto sock = net::open_socket(ctx, AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                    std::array<std::byte, 64> buffer{};
                    sock.bind(*net::ip_endpoint::from_string("127.0.0.1:4242"));
                    auto [bytes_received, from] = co_await net::async_recv_from(
                        sock, std::as_writable_bytes(std::span{buffer.data(), buffer.size()}));
                    co_return bytes_received;
                }(),
                [&]() -> task<size_t> {
                    auto sock = net::open_socket(ctx, AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                    const char buffer[] = {"hello world !!!"};
                    co_await schedule_after(ctx, 10ms);
                    auto bytes_sent = co_await net::async_send_to(sock, as_bytes(std::span{buffer}),
                                                                  *net::ip_endpoint::from_string("127.0.0.1:4242"));
                    co_return bytes_sent;
                }(),
                async_exec(ctx, stop_source.get_token())}
            .sync_wait();
    REQUIRE(tx_bytes != 0);
    REQUIRE(rx_bytes == tx_bytes);
}

TEST_CASE("udp has_pending_data test", "[g6::net::udp]") {
    io::context ctx{};
    std::stop_source stop_source{};

    using namespace std::chrono_literals;

    spawner{[&]() -> task<void> {
                scope_guard _ = [&]() noexcept { stop_source.request_stop(); };
                auto sock = net::open_socket(ctx, AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                std::array<std::byte, 64> buffer{};
                sock.bind(*net::ip_endpoint::from_string("127.0.0.1:4242"));
                REQUIRE_FALSE(net::has_pending_data(sock));
                co_await schedule_after(ctx, 10ms);
                REQUIRE(net::pending_bytes(sock) == 16);
            }(),
            [&]() -> task<void> {
                auto sock = net::open_socket(ctx, AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                const char buffer[] = {"hello world !!!"};
                auto bytes_sent = co_await net::async_send_to(sock, std::as_bytes(std::span{buffer}),
                                                              *net::ip_endpoint::from_string("127.0.0.1:4242"));
            }(),
            async_exec(ctx, stop_source.get_token())}
        .sync_wait();
}
