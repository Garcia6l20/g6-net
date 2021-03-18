#ifndef G6_CONFIG_HPP_
#define G6_CONFIG_HPP_

#if defined(__linux)
#define G6_OS_LINUX true
#define G6_OS_WINDOWS false
#elif defined(_MSC_VER)
#define G6_OS_LINUX false
#define G6_OS_WINDOWS true
#else
#error "Unsupported OS"
#endif

#endif // G6_CONFIG_HPP_
