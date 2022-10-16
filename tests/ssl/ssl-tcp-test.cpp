#include <catch2/catch.hpp>

#include <fmt/core.h>
#include <g6/coro/sync_wait.hpp>
#include <g6/net/ip_endpoint.hpp>
#include <g6/scope_guard.hpp>

#include <g6/io/context.hpp>
#include <g6/ssl/async_socket.hpp>

#include <cert.hpp>

using namespace g6;
using namespace std::chrono_literals;

TEST_CASE("g6::net::ssl tcp tx/rx test", "[g6][net][ssl][tcp]") {
    io::context ctx{};
    std::stop_source stop_source{};

    const ssl::certificate certificate{cert};
    const ssl::private_key private_key{key};

    auto server = net::open_socket(ctx, net::proto::secure_tcp);
    server.bind(*from_string<net::ip_endpoint>("127.0.0.1:0"));
    server.host_name("localhost");
    server.set_certificate(certificate);
    server.set_private_key(private_key);
    server.set_peer_verify_mode(ssl::peer_verify_mode::optional);
    server.set_verify_flags(ssl::verify_flags::allow_untrusted);

    auto server_endpoint = *server.local_endpoint();

    fmt::print("server endpoint: {}\n", server_endpoint);

    auto [server_result, client_result, _] = sync_wait(
        [&]() -> task<size_t> {
            server.listen();
            auto [session, client_address] = co_await net::async_accept(server);
            char buffer[1024]{};
            try {
                auto received = co_await net::async_recv(session, std::span{buffer});
                fmt::print("server received {} bytes\n", received);
                co_await net::async_send(session, std::span{buffer, received});
                co_return received;
            } catch (std::system_error &error) {
                fmt::print("server error: {}\n", error.what());
                co_return std::numeric_limits<size_t>::max();
            }
        }(),
        [&]() -> task<size_t> {
            scope_guard _ = [&]() noexcept { stop_source.request_stop(); };
            auto client = net::open_socket(ctx, net::proto::secure_tcp);
            client.bind(*from_string<net::ip_endpoint>("127.0.0.1:0"));
            client.host_name("localhost");
            client.set_peer_verify_mode(ssl::peer_verify_mode::required);
            client.set_verify_flags(ssl::verify_flags::allow_untrusted);
            co_await net::async_connect(client, server_endpoint);
            const char buffer[] = {"hello world !!!"};
            auto sent = co_await net::async_send(client, std::span{buffer});
            fmt::print("client sent: {} bytes\n", sent);
            char rx_buffer[64];
            auto rx_bytes = co_await net::async_recv(client, std::span{rx_buffer});
            REQUIRE(std::memcmp(buffer, rx_buffer, rx_bytes) == 0);
            co_return sent;
        }(),
        async_exec(ctx, stop_source.get_token()));
    REQUIRE(server_result == client_result);
}
