#include <catch2/catch.hpp>

#include <unifex/sync_wait.hpp>
#include <unifex/task.hpp>
#include <unifex/when_all.hpp>

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
                      scope_guard _ = [&]() noexcept {
                          stop_source.request_stop();
                      };
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
              transform([](auto &&received, auto &&sent, ...) {
                  REQUIRE(sent == received);
              }));
}

TEST_CASE("tcp server/client test", "[g6::net::tcp]") {
    io::context ctx{};
    inplace_stop_source stop_source{};

    sync_wait(when_all(
        [&]() -> task<size_t> {
          scope_guard _ = [&]() noexcept {
            stop_source.request_stop();
          };
          auto server = net::open_socket(ctx,
                                         net::tcp_server,
                                         *net::ip_endpoint::from_string("127.0.0.1:4242"));
          auto [client, client_address] = co_await net::async_accept(server);
          char buffer[1024]{};
          auto byte_count = co_await net::async_recv(client, as_writable_bytes(span{buffer}));
          co_return byte_count;
        }(),
        [&]() -> task<size_t> {
          auto sock = co_await net::open_socket(ctx, net::tcp_client, *net::ip_endpoint::from_string("127.0.0.1:4242"));
          const char buffer[] = {"hello world !!!"};
          auto sent = co_await net::async_send(sock, as_bytes(span{buffer}));
          co_return sent;
        }(),
        [&]() -> task<void> {
          ctx.run(stop_source.get_token());
          co_return;
        }()) |
              transform([](auto &&received, auto &&sent, ...) {
                REQUIRE(sent == received);
              }));
}
