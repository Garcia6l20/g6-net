#include <catch2/catch.hpp>

#include <QApplication>
#include <QMainWindow>
#include <QPushButton>
#include <QTimer>


#include <QtPlugin>

Q_IMPORT_PLUGIN(QWindowsIntegrationPlugin)

#include <g6/cpo/exec.hpp>
#include <g6/cpo/scheduler.hpp>
#include <g6/scope_guard.hpp>
#include <g6/sync_wait.hpp>

namespace g6 {
    class ui_context : public QApplication {
        using QApplication::QApplication;

        friend auto tag_invoke(tag<async_exec>, ui_context &ctx, std::stop_token const &stop = {}) -> task<int> {
            std::stop_callback stop_requested{stop, [&] { ctx.quit(); }};
            co_return ctx.exec();
        }

    public:
        class schedule_after_operation : QTimer {
        public:
            template<typename Rep, typename Per>
            schedule_after_operation(std::chrono::duration<Rep, Per> duration) {
                setInterval(std::chrono::duration_cast<std::chrono::milliseconds>(duration));
                setSingleShot(true);
            }

            bool await_ready() const noexcept { return false; }
            void await_suspend(std::coroutine_handle<> awaiter) noexcept {
                connect(this, &QTimer::timeout, [awaiter] { awaiter.resume(); });
                start();
            }
            void await_resume() const noexcept {}
        };

        template<typename Rep, typename Per>
        friend auto tag_invoke(tag<schedule_after>, ui_context &, std::chrono::duration<Rep, Per> duration) {
            return schedule_after_operation{duration};
        }

        friend auto tag_invoke(tag<schedule>, ui_context &) {
            return schedule_after_operation{std::chrono::milliseconds{0}};
        }
    };

    class widget : public QWidget {
        using QWidget::QWidget;
    };

    template<auto Sig, typename ObjectT>
    class signal_awaiter {
    public:
        template<typename... Args>
        struct args_list_to_tuple {
            using type = std::tuple<Args...>;
        };

        template<typename... Args>
        struct args_list_to_tuple<QtPrivate::List<Args...>> : args_list_to_tuple<Args...> {};

        using result_t = args_list_to_tuple<typename QtPrivate::FunctionPointer<decltype(Sig)>::Arguments>::type;

        signal_awaiter(ObjectT *object) noexcept : object_{object} {}

        bool await_ready() const noexcept { return false; }
        void await_suspend(std::coroutine_handle<> awaiter) {
            QObject::connect(object_, Sig, [this, awaiter](auto &&...result) {
                result_ = std::move(result);
                awaiter.resume();
            });
        }
        auto await_resume() const noexcept { return result_.value(); };

    private:
        ObjectT *object_;
        std::optional<result_t> result_;
    };

    template<auto Sig, typename ObjectT>
    signal_awaiter<Sig, ObjectT> signal(ObjectT *obj) {
        return {obj};
    };
}// namespace g6

class TestWidget : g6::widget {

public:
    TestWidget() : widget{} {}
};

using namespace std::chrono_literals;

TEST_CASE("Qt test") {
    const char *argv[] = {{"test"}};
    int argc = sizeof(argv) / sizeof(argv[0]);
    std::stop_source stop;
    g6::ui_context ctx{argc, const_cast<char **>(argv)};
    g6::sync_wait(
        [&]() -> g6::task<> {
            co_await g6::schedule_after(ctx, 500ms);
            QPushButton btn{"Click me !"};
            btn.show();
            co_await g6::signal<&QPushButton::clicked>(&btn);
            stop.request_stop();
        }(),
        g6::async_exec(ctx, stop.get_token()));
}
