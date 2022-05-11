
#include <g6/coro/sync_wait.hpp>
#include <g6/io/context.hpp>
#include <g6/net/async_socket.hpp>
#include <g6/scope_guard.hpp>

#include <fmt/format.h>

using namespace g6;
using namespace std::chrono_literals;

int main() {
    io::context ctx{};
    std::stop_source stop_source{};

    sync_wait(
        [&]() -> task<void> {
            scope_guard _ = [&]() noexcept { stop_source.request_stop(); };
            try {
                auto sock = net::open_socket(ctx, net::proto::tcp);
                sock.bind(*from_string<net::ip_endpoint>("127.0.0.1:4242"));
                sock.listen();
                auto [client, client_address] = co_await net::async_accept(sock);
                char buffer[1024]{};
                auto byte_count = co_await net::async_recv(client, as_writable_bytes(std::span{buffer}));
                fmt::print("received: {} bytes from {}: {}\n", byte_count, client_address,
                           std::string_view{buffer, byte_count});
            } catch (std::exception const &ex) { fmt::print("server failed: {}\n", ex.what()); }
        }(),
        [&]() -> task<void> {
            try {
                auto sock = net::open_socket(ctx, net::proto::tcp);
                sock.bind(*from_string<net::ip_endpoint>("127.0.0.1:0"));
                co_await net::async_connect(sock, *from_string<net::ip_endpoint>("127.0.0.1:4242"));
                constexpr std::string_view hello{"hello world !!!"};
                co_await net::async_send(sock, as_bytes(std::span{hello.data(), hello.size()}));
            } catch (std::exception const &ex) {
                fmt::print("client failed: {}\n", ex.what());
                stop_source.request_stop();
            }
        }(),
        async_exec(ctx, stop_source.get_token()));
}
