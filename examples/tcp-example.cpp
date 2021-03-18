#include <unifex/sync_wait.hpp>
#include <unifex/task.hpp>
#include <unifex/when_all.hpp>

#include <g6/io/context.hpp>
#include <g6/net/ip_endpoint.hpp>
#include <g6/net/tcp.hpp>

#include <fmt/format.h>

using namespace g6;
using namespace std::chrono_literals;

int main() {
    io::context ctx{};
    inplace_stop_source stop_source{};

    sync_wait(when_all(
        [&]() -> task<void> {
            scope_guard _ = [&]() noexcept {
                stop_source.request_stop();
            };
            auto sock = net::open_socket(ctx, net::tcp_server, *net::ip_endpoint::from_string("127.0.0.1:4242"));
            auto [client, client_address] = co_await net::async_accept(sock);
            char buffer[1024]{};
            auto byte_count = co_await net::async_recv(client, as_writable_bytes(span{buffer}));
            fmt::print("received: {} bytes from {}: {}\n", byte_count, client_address.to_string(), std::string_view{buffer, byte_count});
            co_return;
        }(),
        [&]() -> task<void> {
          auto sock = co_await net::open_socket(ctx, net::tcp_client, *net::ip_endpoint::from_string("127.0.0.1:4242"));
          const char buffer[] = {"hello world !!!"};
          co_await net::async_send(sock, as_bytes(span{buffer}));
        }(),
        [&]() -> task<void> {
            ctx.run(stop_source.get_token());
            co_return;
        }()));
}
