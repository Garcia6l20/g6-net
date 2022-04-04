#pragma once

namespace g6 {
    template<typename Fn>
    class scope_guard {
    public:
        scope_guard(Fn &&fn) noexcept : fn_{std::forward<Fn>(fn)} {}
        ~scope_guard() noexcept(std::is_nothrow_invocable_v<Fn>) {
            if (enabled_) { std::invoke(fn_); }
        }
        void disable() noexcept { enabled_ = false; }

    private:
        bool enabled_{true};
        Fn fn_;
    };
}// namespace g6
