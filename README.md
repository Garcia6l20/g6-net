# G6 network library

This library extends libunifex functionality to provide networking primitives.

CPOs:
- open_socket
- async_accept
- async_connect
- async_send
- async_send_to
- async_recv
- async_recv_from

## Supported contexts

Only `io_uring_context` executor is actually supported, it is extended by `g6::io::context`
which provides extra functionalities (and supports inheritance).

I'm planning to add support to `low_latency_iocp_context` soon.

## Clone the project

```bash
git clone --recurse-submodules https://github.com/Garcia6l20/g6-net.git
```

## Build the project

```bash
mkdir build && cd build
conan install --build=outdated ..
cmake ..
cmake --build .
```
