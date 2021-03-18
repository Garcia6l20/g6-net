#include <unifex/sync_wait.hpp>
#include <unifex/task.hpp>
#include <unifex/when_all.hpp>

#include <g6/io/context.hpp>
#include <g6/net/ip_endpoint.hpp>
#include <g6/net/async_socket.hpp>

#include <iostream>

using namespace g6;

int main() {
    io::context ctx{};
    inplace_stop_source stop_source{};

    sync_wait(when_all(
        [&]() -> task<void> {
            scope_guard _ = [&]() noexcept {
                stop_source.request_stop();
            };
            auto sock = net::open_socket(ctx, AF_INET, SOCK_DGRAM);
            std::array<std::byte, 64> buffer{};
            sock.bind(*net::ip_endpoint::from_string("127.0.0.1:4242"));
            auto [bytes_received, from] = co_await g6::net::async_recv_from(sock, as_writable_bytes(span{buffer}));
            std::cout << "received " << bytes_received << " bytes from '" << from.to_string() << "': "
                      << std::string_view{reinterpret_cast<char*>(buffer.data()), bytes_received} << '\n';
            co_return;
        }(),
        [&]() -> task<void> {
            auto sock = net::open_socket(ctx, AF_INET, SOCK_DGRAM);
            const char buffer[] = {"hello world !!!"};
            auto bytes_sent = co_await g6::net::async_send_to(sock, as_bytes(span{buffer}), *g6::net::ip_endpoint::from_string("127.0.0.1:4242"));
            co_return;
        }(),
        [&]() -> task<void> {
            ctx.run(stop_source.get_token());
            co_return;
        }()));
}
