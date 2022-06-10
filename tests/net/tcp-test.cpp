#include <catch2/catch.hpp>

#include <fmt/format.h>

#include <g6/coro/sync_wait.hpp>

#include <g6/io/context.hpp>
#include <g6/net/async_socket.hpp>
#include <g6/net/ip_endpoint.hpp>
#include <g6/scope_guard.hpp>


using namespace g6;
using namespace std::chrono_literals;

TEST_CASE("tcp stop server test", "[g6::net::tcp]") {
    io::context ctx{};
    std::stop_source stop_accept{};
    std::stop_source stop_run{};

    spawner{[&]() -> task<void> {
                auto _ = scope_guard{[&] { stop_run.request_stop(); }};
                auto sock = net::open_socket(ctx, net::proto::tcp);
                sock.bind(*from_string<net::ip_endpoint>("127.0.0.1:0"));
                sock.listen();
                try {
                    auto [client, client_address] = co_await net::async_accept(sock, stop_accept.get_token());
                    FAIL("Should have been cancelled");
                } catch (std::system_error const &err) { REQUIRE(err.code() == std::errc::operation_canceled); }
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

    auto server = net::open_socket(ctx, net::proto::tcp);
    server.bind(*from_string<net::ip_endpoint>("127.0.0.1:0"));
    auto server_endpoint = *server.local_endpoint();

    auto [received, sent, _] = spawner{
        [&]() -> task<size_t> {
            server.listen();
            auto [client, client_address] = co_await net::async_accept(server);
            fmt::print("new client connected (local: {}, remote: {})\n", *client.local_endpoint(),
                       *client.remote_endpoint());
            char buffer[1024]{};
            auto byte_count = co_await net::async_recv(client, as_writable_bytes(std::span{buffer}));
            co_await net::async_send(client, as_bytes(std::span{buffer, byte_count}));
            co_return byte_count;
        }(),
        [&]() -> task<size_t> {
            scope_guard _ = [&]() noexcept { stop_source.request_stop(); };
            auto sock = net::open_socket(ctx, net::proto::tcp);
            sock.bind(*from_string<net::ip_endpoint>("127.0.0.1:0"));
            co_await net::async_connect(sock, server_endpoint);
            fmt::print("client connected (local: {}, remote: {})\n", *sock.local_endpoint(), *sock.remote_endpoint());
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

TEST_CASE("tcp tx/rx stream test", "[g6::net::tcp]") {
    io::context ctx{};
    std::stop_source stop_source{};

    auto server = net::open_socket(ctx, net::proto::tcp);
    server.bind(*from_string<net::ip_endpoint>("127.0.0.1:0"));
    auto server_endpoint = *server.local_endpoint();

    auto [received, sent, _] = sync_wait(
        [&]() -> task<size_t> {
            server.listen();
            auto [client, client_address] = co_await net::async_accept(server);
            fmt::print("new client connected (local: {}, remote: {})\n", *client.local_endpoint(),
                       *client.remote_endpoint());
            std::string data;
            co_await net::async_recv(client, std::back_inserter(data));
            fmt::print("data: {}\n", data);
            co_return data.size();
        }(),
        [&]() -> task<size_t> {
            scope_guard _{[&]() noexcept {//
                stop_source.request_stop();
            }};
            auto sock = net::open_socket(ctx, net::proto::tcp);
            sock.bind(*from_string<net::ip_endpoint>("127.0.0.1:0"));
            co_await net::async_connect(sock, server_endpoint);
            fmt::print("client connected (local: {}, remote: {})\n", *sock.local_endpoint(), *sock.remote_endpoint());
            constexpr auto data = std::string_view{"hello world !!!"};
            auto sent = co_await net::async_send(sock, data);
            sent += co_await net::async_send(sock, data);
            sent += co_await net::async_send(sock, data);
            co_return sent;
        }(),
        async_exec(ctx, stop_source.get_token()));

    REQUIRE(sent == received);
}