#include <catch2/catch.hpp>

#include <QApplication>
#include <QTimer>


#include <QtPlugin>

#if G6_OS_WINDOWS
Q_IMPORT_PLUGIN(QWindowsIntegrationPlugin)
#else
Q_IMPORT_PLUGIN(QXcbIntegrationPlugin)
#endif

#include <g6/cpo/exec.hpp>
#include <g6/cpo/scheduler.hpp>
#include <g6/cpo/spawn.hpp>
#include <g6/scope_guard.hpp>
#include <g6/sync_wait.hpp>

namespace g6::qt {
    class context : public QApplication, public g6::ff_spawner {
        using QApplication::QApplication;

        friend auto tag_invoke(tag<async_exec>, context &ctx, std::stop_token const &stop = {}) -> task<int> {
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
        friend auto tag_invoke(tag<schedule_after>, context &, std::chrono::duration<Rep, Per> duration) {
            return schedule_after_operation{duration};
        }

        friend auto tag_invoke(tag<schedule>, context &) {
            return schedule_after_operation{std::chrono::milliseconds{0}};
        }

        friend auto tag_invoke(tag<g6::spawn>, context &ctx, task<> &&task) { ctx.spawn(std::move(task)); }

        static inline g6::qt::context &current = static_cast<g6::qt::context &>(*qApp);
    };

    namespace details {
        template<typename SignalT, typename ObjectT>
        class signal_awaiter;
    }

    template<typename SignalT, typename ObjectT>
    details::signal_awaiter<SignalT, ObjectT> signal(ObjectT *obj, SignalT signal) {
        return {obj, signal};
    };

    namespace details {
        template<typename SignalT, typename ObjectT>
        class signal_awaiter {

            template<typename _SignalT, typename _ObjectT>
            friend signal_awaiter<_SignalT, _ObjectT> qt::signal(_ObjectT *obj, _SignalT signal);

            template<typename... Args>
            struct args_list_to_tuple {
                using type = std::tuple<Args...>;
            };

            template<typename... Args>
            struct args_list_to_tuple<QtPrivate::List<Args...>> : args_list_to_tuple<Args...> {};


            using result_t = args_list_to_tuple<typename QtPrivate::FunctionPointer<SignalT>::Arguments>::type;
            static constexpr size_t args_count = QtPrivate::FunctionPointer<SignalT>::ArgumentCount;

            signal_awaiter(ObjectT *object, SignalT signal) noexcept : object_{object}, signal_{signal} {}

        public:
            bool await_ready() const noexcept { return false; }
            void await_suspend(std::coroutine_handle<> awaiter) {
                con_ = QObject::connect(object_, signal_, [this, awaiter](auto &&...result) {
                    result_ = std::make_tuple(std::forward<decltype(result)>(result)...);
                    QObject::disconnect(con_);
                    awaiter.resume();
                });
            }
            auto await_resume() const noexcept {
                if constexpr (args_count == 1) {
                    return std::get<0>(result_.value());
                } else if constexpr (args_count > 1) {
                    return result_.value();
                }
            };

        private:
            ObjectT *object_;
            SignalT signal_;
            std::optional<result_t> result_;
            QMetaObject::Connection con_;
        };
    }// namespace details

}// namespace g6::qt

#include <QMainWindow>
#include <QPushButton>

class TestWidget : QWidget {

public:
    TestWidget() : QWidget{} {}
};

using namespace std::chrono_literals;
using namespace g6;

TEST_CASE("Qt test") {
    const char *argv[] = {{"test"}};
    int argc = sizeof(argv) / sizeof(argv[0]);
    std::stop_source stop;
    qt::context ctx{argc, const_cast<char **>(argv)};
    sync_wait(
        [&stop]() -> g6::task<> {
            co_await schedule_after(qt::context::current, 500ms);
            QPushButton btn{"Click me !"};
            btn.setCheckable(true);
            btn.show();
            bool result = co_await qt::signal(&btn, &QPushButton::clicked);
            REQUIRE(result == true);
            btn.setText("Again !!!");
            result = co_await qt::signal(&btn, &QPushButton::clicked);
            REQUIRE(result == false);
            stop.request_stop();
        }(),
        async_exec(ctx, stop.get_token()));
}
