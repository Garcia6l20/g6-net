#ifndef G6_IO_CONFIG_HPP_
#define G6_IO_CONFIG_HPP_

#include <g6/config.hpp>

#if G6_OS_LINUX
#if not defined(G6_NO_IO_URING) and __has_include(<liburing.h>)
#define G6_IO_USE_IO_URING_CONTEXT true
#define G6_IO_USE_EPOLL_CONTEXT false
#else
#define G6_IO_USE_IO_URING_CONTEXT false
#define G6_IO_USE_EPOLL_CONTEXT true
#endif
#define G6_IO_USE_IOCP_CONTEXT false
#elif G6_OS_WINDOWS
#define G6_IO_USE_IO_URING_CONTEXT false
#define G6_IO_USE_EPOLL_CONTEXT false
#define G6_IO_USE_IOCP_CONTEXT true
#endif

#endif // G6_IO_CONFIG_HPP_