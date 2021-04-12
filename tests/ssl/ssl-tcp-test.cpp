#include <catch2/catch.hpp>

#include <unifex/sync_wait.hpp>
#include <unifex/task.hpp>
#include <unifex/transform.hpp>
#include <unifex/when_all.hpp>

#include <g6/io/context.hpp>
#include <g6/net/ip_endpoint.hpp>
#include <g6/ssl/async_socket.hpp>

#include <cert.hpp>

using namespace g6;
using namespace std::chrono_literals;

TEST_CASE("ssl tcp tx/rx test", "[g6::ssl::tcp]") {
    spdlog::set_level(spdlog::level::debug);

    io::context ctx{};
    auto sched = ctx.get_scheduler();
    inplace_stop_source stop_source{};

    const ssl::certificate certificate{cert};
    const ssl::private_key private_key{key};

    auto server =
        net::open_socket(ctx, ssl::tcp_server, *net::ip_endpoint::from_string("127.0.0.1:0"), certificate, private_key);
    server.host_name("localhost");
    server.set_peer_verify_mode(ssl::peer_verify_mode::optional);
    server.set_verify_flags(ssl::verify_flags::allow_untrusted);

    auto server_endpoint = *server.local_endpoint();

    spdlog::info("server endpoint: {}", server_endpoint.to_string());

    sync_wait(
        when_all(
            [&]() -> task<size_t> {
                scope_guard _ = [&]() noexcept { stop_source.request_stop(); };
                server.listen();
                auto [session, client_address] = co_await net::async_accept(server);
                char buffer[1024]{};
                try {
                    auto received = co_await net::async_recv(session, as_writable_bytes(span{buffer}));
                    spdlog::info("server received {} bytes", received);
                    co_return received;
                } catch (std::system_error &error) {
                    spdlog::error("server error: {}", error.what());
                    co_return std::numeric_limits<size_t>::max();
                }
            }(),
            [&]() -> task<size_t> {
                auto client = net::open_socket(ctx, ssl::tcp_client);
                client.host_name("localhost");
                client.set_peer_verify_mode(ssl::peer_verify_mode::required);
                client.set_verify_flags(ssl::verify_flags::allow_untrusted);
                co_await net::async_connect(client, server_endpoint);
                const char buffer[] = {"hello world !!!"};
                auto sent = co_await net::async_send(client, as_bytes(span{buffer}));
                spdlog::info("client sent: {} bytes", sent);
                co_return sent;
            }(),
            [&]() -> task<void> {
                ctx.run(stop_source.get_token());
                co_return;
            }())
        | transform([](auto &&server_result, auto &&client_result, ...) { REQUIRE(server_result == client_result); }));
    spdlog::debug("done");
}
