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
    io::context ctx{};
    inplace_stop_source stop_source{};

    ssl::certificate certificate{cert};
    ssl::private_key private_key{key};

    sync_wait(
        when_all(
            [&]() -> task<size_t> {
                scope_guard _ = [&]() noexcept { stop_source.request_stop(); };
                auto sock = net::open_socket(ctx.get_scheduler(), certificate, private_key);
                sock.bind(*net::ip_endpoint::from_string("127.0.0.1:4242"));
                sock.listen();
                auto [client, client_address] = co_await net::async_accept(sock);
//                char buffer[1024]{};
//                auto byte_count = co_await net::async_recv(client, as_writable_bytes(span{buffer}));
//                co_return byte_count;
              co_return 0;
            }(),
            [&]() -> task<size_t> {
                //                      auto sock = net::open_socket(ctx.get_scheduler(), AF_INET, SOCK_STREAM);
                //                      co_await net::async_connect(sock, *net::ip_endpoint::from_string("127.0.0.1:4242"));
                //                      const char buffer[] = {"hello world !!!"};
                //                      auto sent = co_await net::async_send(sock, as_bytes(span{buffer}));
                //                      co_return sent;
                co_return 0;
            }(),
            [&]() -> task<void> {
                ctx.run(stop_source.get_token());
                co_return;
            }()) |
        transform([](auto &&received, auto &&sent, ...) { REQUIRE(sent == received); }));
}
