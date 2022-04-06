#include <catch2/catch.hpp>

#include <fmt/format.h>

#include <g6/io/context.hpp>
#include <g6/net/async_socket.hpp>
#include <g6/net/ip_endpoint.hpp>
#include <g6/spawner.hpp>


using namespace g6;
using namespace std::chrono_literals;

TEST_CASE("tcp stop server test", "[g6::net::tcp]") {
    io::context ctx{};
    std::stop_source stop_accept{};
    std::stop_source stop_run{};

    spawner{[&]() -> task<void> {
                auto _ = scope_guard{[&] { stop_run.request_stop(); }};
                auto sock = net::open_socket(ctx, net::protos::tcp);
                sock.bind(*net::ip_endpoint::from_string("127.0.0.1:0"));
                sock.listen();
                try {
                    auto [client, client_address] = co_await net::async_accept(sock, stop_accept.get_token());
                    FAIL("Should have been cancelled");
                } catch (std::system_error &&err) { REQUIRE(err.code() == std::errc::operation_canceled); }
            }(),
            [&]() -> task<void> {
                co_await schedule_after(ctx, 100ms);
                stop_accept.request_stop();
            }(),
            async_exec(ctx, stop_run.get_token())}
        .sync_wait();
}

TEST_CASE("tcp tx/rx test", "[g6::net::tcp]") {
    io::context ctx{};
    std::stop_source stop_source{};

    auto server_endpoint = *net::ip_endpoint::from_string("127.0.0.1:4242");

    auto [received, sent, _] =
        spawner{[&]() -> task<size_t> {
                    auto sock = net::open_socket(ctx, net::protos::tcp);
                    sock.bind(server_endpoint);
                    sock.listen();
                    auto [client, client_address] = co_await net::async_accept(sock);
                    fmt::print("new client connected (local: {}, remote: {})\n", client.local_endpoint()->to_string(),
                               client.remote_endpoint()->to_string());
                    char buffer[1024]{};
                    auto byte_count = co_await net::async_recv(client, as_writable_bytes(std::span{buffer}));
                    co_await net::async_send(client, as_bytes(std::span{buffer, byte_count}));
                    co_return byte_count;
                }(),
                [&]() -> task<size_t> {
                    scope_guard _ = [&]() noexcept { stop_source.request_stop(); };
                    auto sock = net::open_socket(ctx, net::protos::tcp);
                    sock.bind(*net::ip_endpoint::from_string("127.0.0.1:0"));
                    co_await net::async_connect(sock, server_endpoint);
                    fmt::print("client connected (local: {}, remote: {})\n", sock.local_endpoint()->to_string(),
                               sock.remote_endpoint()->to_string());
                    const char buffer[] = {"hello world !!!"};
                    auto sent = co_await net::async_send(sock, as_bytes(std::span{buffer}));
                    char rx_buffer[1024]{};
                    auto rx_bytes = co_await net::async_recv(sock, as_writable_bytes(std::span{rx_buffer}));
                    REQUIRE(std::memcmp(rx_buffer, buffer, rx_bytes) == 0);
                    co_return sent;
                }(),
                async_exec(ctx, stop_source.get_token())}
            .sync_wait();

    REQUIRE(sent == received);
}
