#ifndef G6_NET_IMPL_SOCKET_OPTION_HPP_
#define G6_NET_IMPL_SOCKET_OPTION_HPP_

namespace g6::net {
    template<int so_level, int opt_name, typename UserT, typename ImplT>
    void simple_scoket_option<so_level, opt_name, UserT, ImplT>::set_impl(auto fd, UserT value) {
        auto impl_value = static_cast<ImplT>(value);
        if (setsockopt(fd, so_level, opt_name, reinterpret_cast<const char *>(&impl_value), sizeof(impl_value)) < 0) {
            using namespace std::literals;
            throw std::system_error{errno, std::system_category()};
        }
    }
    template<int so_level, int opt_name, typename UserT, typename ImplT>
    UserT simple_scoket_option<so_level, opt_name, UserT, ImplT>::get_impl(auto fd) {
        ImplT impl_value{};
        int impl_size = sizeof(impl_value);
        if (getsockopt(fd, so_level, opt_name, reinterpret_cast<char *>(&impl_value), &impl_size) < 0) {
            using namespace std::literals;
            throw std::system_error{errno, std::system_category()};
        }
        return static_cast<UserT>(impl_value);
    }

    template<int so_level, int opt_name>
    void empty_socket_option<so_level, opt_name>::set_impl(auto fd) {
        if (setsockopt(fd, so_level, opt_name, nullptr, 0) < 0) {
            using namespace std::literals;
            throw std::system_error{errno, std::system_category()};
        }
    }
    template<int so_level, int opt_name>
    void empty_socket_option<so_level, opt_name>::get_impl(auto fd) {
        std::abort();
    }
}// namespace g6::net

#endif// G6_NET_IMPL_SOCKET_OPTION_HPP_
