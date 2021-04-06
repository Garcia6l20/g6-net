#include <catch2/catch.hpp>

#include <unifex/just.hpp>
#include <unifex/let.hpp>
#include <unifex/sync_wait.hpp>
#include <unifex/task.hpp>
#include <unifex/when_all.hpp>

#include <fmt/format.h>

#include <g6/io/context.hpp>
#include <g6/net/async_socket.hpp>
#include <g6/net/ip_endpoint.hpp>
#include <g6/net/tcp.hpp>

using namespace g6;
using namespace std::chrono_literals;

TEST_CASE("tcp tx/rx test", "[g6::net::tcp]") {
    io::context ctx{};
    inplace_stop_source stop_source{};

    sync_wait(when_all(
                  [&]() -> task<size_t> {
                      scope_guard _ = [&]() noexcept { stop_source.request_stop(); };
                      auto sock = net::open_socket(ctx, AF_INET, SOCK_STREAM);
                      sock.bind(*net::ip_endpoint::from_string("127.0.0.1:4242"));
                      sock.listen();
                      auto [client, client_address] = co_await net::async_accept(sock);
                      char buffer[1024]{};
                      auto byte_count = co_await net::async_recv(client, as_writable_bytes(span{buffer}));
                      co_return byte_count;
                  }(),
                  [&]() -> task<size_t> {
                      auto sock = net::open_socket(ctx, AF_INET, SOCK_STREAM);
                      co_await net::async_connect(sock, *net::ip_endpoint::from_string("127.0.0.1:4242"));
                      const char buffer[] = {"hello world !!!"};
                      auto sent = co_await net::async_send(sock, as_bytes(span{buffer}));
                      co_return sent;
                  }(),
                  [&]() -> task<void> {
                      ctx.run(stop_source.get_token());
                      co_return;
                  }()) |
              transform([](auto &&received, auto &&sent, ...) { REQUIRE(sent == received); }));
}

TEST_CASE("tcp server/client test", "[g6::net::tcp]") {
    io::context ctx{};
    inplace_stop_source stop_source{};

    sync_wait(when_all(
                  [&]() -> task<size_t> {
                      scope_guard _ = [&]() noexcept { stop_source.request_stop(); };
                      auto server =
                          net::open_socket(ctx, net::tcp_server, *net::ip_endpoint::from_string("127.0.0.1:4242"));
                      auto [client, client_address] = co_await net::async_accept(server);
                      char buffer[1024]{};
                      auto byte_count = co_await net::async_recv(client, as_writable_bytes(span{buffer}));
                      co_return byte_count;
                  }(),
                  [&]() -> task<size_t> {
                      auto sock = co_await net::open_socket(ctx, net::tcp_client,
                                                            *net::ip_endpoint::from_string("127.0.0.1:4242"));
                      const char buffer[] = {"hello world !!!"};
                      auto sent = co_await net::async_send(sock, as_bytes(span{buffer}));
                      co_return sent;
                  }(),
                  [&]() -> task<void> {
                      ctx.run(stop_source.get_token());
                      co_return;
                  }()) |
              transform([](auto &&received, auto &&sent, ...) { REQUIRE(sent == received); }));
}

TEST_CASE("tcp server/client coroless test", "[g6::net::tcp]") {
    io::context ctx{};
    inplace_stop_source stop_source{};
    std::thread t{[&] { ctx.run(stop_source.get_token()); }};
    scope_guard stop_on_exit = [&]() noexcept {
        stop_source.request_stop();
        t.join();
    };

    struct {
        net::async_socket sock;
        char buffer[1024]{};
    } server{net::open_socket(ctx, net::tcp_server, *net::ip_endpoint::from_string("127.0.0.1:0"))};

    struct {
        std::string_view tx_data = "Hello world !!";
        char buffer[1024]{};
    } client;

    sync_wait(
        when_all(let(net::async_accept(server.sock),
                     [&server](auto &clt_sock, auto &endpoint) {
                         return let(net::async_recv(clt_sock, as_writable_bytes(span{server.buffer})),
                                    [&](size_t bytes) {
                                        fmt::print("server received {} bytes from {}\n", bytes, endpoint.to_string());
                                        return net::async_send(clt_sock, as_bytes(span{server.buffer, bytes}));
                                    });
                     }),
                 let(net::open_socket(ctx, net::tcp_client, *server.sock.local_endpoint()),
                     [&](auto &clt_socket) {
                         return let(net::async_send(clt_socket, as_bytes(span{client.tx_data.data(), client.tx_data.size()})), [&](size_t bytes) {
                             fmt::print("client sent {} bytes\n", bytes);
                             return net::async_recv(clt_socket, as_writable_bytes(span{client.buffer, bytes})) |
                                    transform([](size_t bytes) {
                                        fmt::print("client received {} bytes\n", bytes);
                                        return bytes;
                                    });
                         });
                     })) |
        transform([](auto server_res, auto client_res) {
            size_t server_bytes = std::get<0>(std::get<0>(server_res));
            size_t client_bytes = std::get<0>(std::get<0>(client_res));
            fmt::print("result: {}/{}\n", client_bytes, server_bytes);
            REQUIRE(client_bytes == server_bytes);
        }));
}
