#include <catch2/catch.hpp>

#include <fmt/format.h>

#include <g6/coro/cancel_after.hpp>
#include <g6/coro/sync_wait.hpp>

#include <g6/io/context.hpp>
#include <g6/net/async_socket.hpp>
#include <g6/net/ip_endpoint.hpp>
#include <g6/scope_guard.hpp>


using namespace g6;
using namespace std::chrono_literals;
using namespace std::string_view_literals;

namespace g6::net {
    template<typename Socket, typename ConnectionBuilder>
    task<> tag_invoke(tag_t<async_serve>, Socket server, ip_endpoint endpoint,
                      ConnectionBuilder con_builder) try {
        server.bind(endpoint);
        auto context = co_await this_coro::get_context;
        while (true) {
            auto [client, client_address] = co_await net::async_accept(server);
            auto t = con_builder(std::move(client));
            if (context) { t.set_context(context.value()); }
            spawn(std::move(t));
        }
    } catch (operation_cancelled const &) {}
}// namespace g6::net


TEST_CASE("g6::net: tcp stop server test", "[g6][net][tcp]") {
    io::context ctx{};
    std::stop_source stop_run{};
    REQUIRE_THROWS_AS(//
        sync_wait(
            [&]() -> task<void> {
                auto _ = scope_guard{[&] { stop_run.request_stop(); }};
                auto sock = net::open_socket(ctx, net::proto::tcp);
                sock.bind(*from_string<net::ip_endpoint>("127.0.0.1:0"));
                sock.listen();
                auto [client, client_address] = co_await (net::async_accept(sock) | async_with(io_timeout{100ms}));
                FAIL("Should have been cancelled");
            }(),
            async_exec(ctx, stop_run.get_token())),
        operation_cancelled);
}

TEST_CASE("g6::net: tcp tx/rx test", "[g6][net][tcp]") {
    io::context ctx{};

    auto server = net::open_socket(ctx, net::proto::tcp);
    server.bind(*from_string<net::ip_endpoint>("127.0.0.1:0"));
    auto server_endpoint = *server.local_endpoint();

    auto [received, sent, _] = sync_wait(
        [&]() -> task<size_t> {
            server.listen();
            auto [client, client_address] = co_await net::async_accept(server);
            fmt::print("new client connected (local: {}, remote: {})\n", *client.local_endpoint(),
                       *client.remote_endpoint());
            char buffer[1024]{};
            auto byte_count = co_await net::async_recv(client, as_writable_bytes(std::span{buffer}));
            co_await net::async_send(client, as_bytes(std::span{buffer, byte_count}));
            try {
                auto rx_bytes = co_await net::async_recv(client, as_writable_bytes(std::span{buffer}));
                FAIL("should have been timed out");
            } catch (operation_cancelled const&) {}
            co_return byte_count;
        }() | async_with(io_timeout{20ms}),
        [&]() -> task<size_t> {
            auto sock = net::open_socket(ctx, net::proto::tcp);
            sock.bind(*from_string<net::ip_endpoint>("127.0.0.1:0"));
            co_await net::async_connect(sock, server_endpoint);
            fmt::print("client connected (local: {}, remote: {})\n", *sock.local_endpoint(), *sock.remote_endpoint());
            const char buffer[] = {"hello world !!!"};
            auto sent = co_await net::async_send(sock, as_bytes(std::span{buffer}));
            char rx_buffer[1024]{};
            auto rx_bytes = co_await net::async_recv(sock, as_writable_bytes(std::span{rx_buffer}));            
            REQUIRE(std::memcmp(rx_buffer, buffer, rx_bytes) == 0);
            co_await schedule_after(ctx, 40ms);
            co_return sent;
        }(),
        async_exec(ctx));

    REQUIRE(sent == received);
}

TEST_CASE("g6::net: tcp tx/rx stream test", "[g6][net][tcp]") {
    io::context ctx{};

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
        async_exec(ctx));

    REQUIRE(sent == received);
}