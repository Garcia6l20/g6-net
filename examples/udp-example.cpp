#include <g6/spawner.hpp>

#include <g6/io/context.hpp>
#include <g6/net/async_socket.hpp>
#include <g6/net/ip_endpoint.hpp>
#include <g6/scope_guard.hpp>

#include <iostream>

using namespace g6;

int main() {
    io::context ctx{};
    std::stop_source stop_source{};

    spawner{[&]() -> task<void> {
                scope_guard _ = [&]() noexcept { stop_source.request_stop(); };
                try {
                    auto sock = net::open_socket(ctx, net::proto::udp);
                    std::array<std::byte, 64> buffer{};
                    sock.bind(*net::ip_endpoint::from_string("127.0.0.1:4242"));
                    auto [bytes_received, from] =
                        co_await g6::net::async_recv_from(sock, as_writable_bytes(std::span{buffer}));
                    std::cout << "received " << bytes_received << " bytes from '" << from.to_string()
                              << "': " << std::string_view{reinterpret_cast<char *>(buffer.data()), bytes_received}
                              << '\n';
                } catch (std::exception const &ex) { std::cerr << "listener failed: " << ex.what() << '\n'; }
            }(),
            [&]() -> task<void> {
                try {
                    auto sock = net::open_socket(ctx, net::proto::udp);
                    sock.bind(*net::ip_endpoint::from_string("127.0.0.1:2424"));
                    const char buffer[] = {"hello world !!!"};
                    auto bytes_sent = co_await g6::net::async_send_to(
                        sock, as_bytes(std::span{buffer}), *g6::net::ip_endpoint::from_string("127.0.0.1:4242"));
                } catch (std::exception const &ex) { std::cerr << "emitter failed: " << ex.what() << '\n'; }
            }(),
            async_exec(ctx, stop_source.get_token())}
        .sync_wait();
}
