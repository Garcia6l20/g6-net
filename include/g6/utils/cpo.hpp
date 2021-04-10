#ifndef G6_UTILS_CPO_HPP_
#define G6_UTILS_CPO_HPP_

#include <unifex/tag_invoke.hpp>

namespace g6::_generic_cpo {
    template<typename Concrete>
    struct generic_cpo {
        template<typename... Args>
        auto operator()(
            Args &&...args) const
            noexcept(unifex::is_nothrow_tag_invocable_v<
                     Concrete,
                     Args...>)
                -> unifex::tag_invoke_result_t<
                    Concrete,
                    Args...> {
            return unifex::tag_invoke(
                *static_cast<Concrete const *>(this), std::forward<Args>(args)...);
        }
    };
}// namespace g6::_generic_cpo

#define G6_CPO_DEF(__name, __ns)                                                         \
    namespace __ns {                                                                     \
        inline const struct __name##_cpo : g6::_generic_cpo::generic_cpo<__name##_cpo> { \
        } __name{};                                                                      \
    }                                                                                    \
    using __ns::__name;

#endif // G6_UTILS_CPO_HPP_
