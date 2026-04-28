#include "dlads/log_tailer.hpp"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

namespace fs = std::filesystem;
using namespace dlads;
using namespace std::chrono_literals;

// ── Test fixture ──────────────────────────────────────────────────────────────
// Creates a unique temp file per test, removes it on teardown.

class LogTailerTest : public ::testing::Test {
protected:
    void SetUp() override {
        path_ = fs::temp_directory_path()
                / ("dlads_tailer_" + std::to_string(::getpid()) +
                   "_" + std::to_string(test_counter_++) + ".log");
        // Create an empty file so the tailer can open it immediately.
        std::ofstream(path_).flush();
    }

    void TearDown() override {
        fs::remove(path_);
    }

    /** Append lines to the watched file (each element gets a '\n'). */
    void append(const std::vector<std::string>& lines) {
        std::ofstream f(path_, std::ios::app);
        for (auto& l : lines) f << l << '\n';
    }

    /** Append a raw string with no extra newline. */
    void append_raw(std::string_view data) {
        std::ofstream f(path_, std::ios::app);
        f << data;
    }

    /**
     * Wait until the collected line count reaches `expected` or the
     * deadline elapses.  Returns true iff count was reached.
     */
    bool wait_for(std::vector<std::string>& collected,
                  std::mutex&               mtx,
                  std::size_t               expected,
                  std::chrono::milliseconds timeout = 3000ms) {
        auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            {
                std::lock_guard<std::mutex> lk(mtx);
                if (collected.size() >= expected) return true;
            }
            std::this_thread::sleep_for(20ms);
        }
        std::lock_guard<std::mutex> lk(mtx);
        return collected.size() >= expected;
    }

    fs::path path_;
    static inline std::atomic<int> test_counter_{ 0 };
};

// ─────────────────────────────────────────────────────────────────────────────
// 1. Basic delivery
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(LogTailerTest, DeliversAllLines) {
    std::vector<std::string> got;
    std::mutex               mtx;

    LogTailer tailer(path_, [&](std::string_view line) {
        std::lock_guard<std::mutex> lk(mtx);
        got.emplace_back(line);
    });
    tailer.start();
    std::this_thread::sleep_for(50ms);  // let tailer attach

    constexpr int N = 1000;
    std::vector<std::string> lines;
    lines.reserve(N);
    for (int i = 0; i < N; ++i) lines.push_back("line_" + std::to_string(i));
    append(lines);

    ASSERT_TRUE(wait_for(got, mtx, N));
    tailer.stop();

    std::lock_guard<std::mutex> lk(mtx);
    ASSERT_EQ(got.size(), static_cast<std::size_t>(N));
    for (int i = 0; i < N; ++i)
        EXPECT_EQ(got[i], "line_" + std::to_string(i));
}

TEST_F(LogTailerTest, SkipsExistingContentOnStart) {
    // Write content BEFORE the tailer starts — it must not be delivered.
    append({"pre_existing_line"});

    std::vector<std::string> got;
    std::mutex               mtx;

    LogTailer tailer(path_, [&](std::string_view line) {
        std::lock_guard<std::mutex> lk(mtx);
        got.emplace_back(line);
    });
    tailer.start();
    std::this_thread::sleep_for(50ms);

    append({"new_line"});
    ASSERT_TRUE(wait_for(got, mtx, 1));
    tailer.stop();

    std::lock_guard<std::mutex> lk(mtx);
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(got[0], "new_line");
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Partial-line buffering
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(LogTailerTest, BuffersIncompleteLines) {
    std::vector<std::string> got;
    std::mutex               mtx;

    LogTailer tailer(path_, [&](std::string_view line) {
        std::lock_guard<std::mutex> lk(mtx);
        got.emplace_back(line);
    });
    tailer.start();
    std::this_thread::sleep_for(50ms);

    // Write first half — no newline yet.
    append_raw("hel");
    std::this_thread::sleep_for(150ms);
    {
        std::lock_guard<std::mutex> lk(mtx);
        EXPECT_TRUE(got.empty()) << "should not fire before newline";
    }

    // Complete the line.
    append_raw("lo\n");
    ASSERT_TRUE(wait_for(got, mtx, 1));
    tailer.stop();

    std::lock_guard<std::mutex> lk(mtx);
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(got[0], "hello");
}

TEST_F(LogTailerTest, HandlesVeryLongLine) {
    std::string long_line(65000, 'x');  // just under one read buffer
    std::vector<std::string> got;
    std::mutex               mtx;

    LogTailer tailer(path_, [&](std::string_view line) {
        std::lock_guard<std::mutex> lk(mtx);
        got.emplace_back(line);
    });
    tailer.start();
    std::this_thread::sleep_for(50ms);

    append({long_line});
    ASSERT_TRUE(wait_for(got, mtx, 1));
    tailer.stop();

    std::lock_guard<std::mutex> lk(mtx);
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(got[0], long_line);
}

TEST_F(LogTailerTest, HandlesMultipleLinesInSingleWrite) {
    std::vector<std::string> got;
    std::mutex               mtx;

    LogTailer tailer(path_, [&](std::string_view line) {
        std::lock_guard<std::mutex> lk(mtx);
        got.emplace_back(line);
    });
    tailer.start();
    std::this_thread::sleep_for(50ms);

    // Write 5 lines in one append — they may arrive in one inotify event.
    append({"a", "b", "c", "d", "e"});
    ASSERT_TRUE(wait_for(got, mtx, 5));
    tailer.stop();

    std::lock_guard<std::mutex> lk(mtx);
    ASSERT_EQ(got.size(), 5u);
    EXPECT_EQ(got[0], "a");
    EXPECT_EQ(got[4], "e");
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Log rotation
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(LogTailerTest, ReattachesAfterRotation) {
    std::vector<std::string> got;
    std::mutex               mtx;

    LogTailer tailer(path_, [&](std::string_view line) {
        std::lock_guard<std::mutex> lk(mtx);
        got.emplace_back(line);
    });
    tailer.start();
    std::this_thread::sleep_for(50ms);

    // Write a pre-rotation line.
    append({"before_rotation"});
    ASSERT_TRUE(wait_for(got, mtx, 1));

    // Simulate rotation: rename the old file, create a fresh one at the same path.
    fs::path rotated = path_.string() + ".1";
    fs::rename(path_, rotated);
    std::this_thread::sleep_for(50ms);
    std::ofstream(path_).flush();          // new empty file
    std::this_thread::sleep_for(150ms);    // give tailer time to re-attach

    append({"after_rotation"});
    ASSERT_TRUE(wait_for(got, mtx, 2));
    tailer.stop();

    fs::remove(rotated);

    std::lock_guard<std::mutex> lk(mtx);
    ASSERT_GE(got.size(), 2u);
    EXPECT_EQ(got[0], "before_rotation");
    EXPECT_EQ(got.back(), "after_rotation");
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Lifecycle
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(LogTailerTest, StopJoinsCleanly) {
    LogTailer tailer(path_, [](std::string_view) {});
    tailer.start();
    std::this_thread::sleep_for(50ms);
    EXPECT_TRUE(tailer.running());

    // stop() must return in well under 1 second.
    auto t0 = std::chrono::steady_clock::now();
    tailer.stop();
    auto elapsed = std::chrono::steady_clock::now() - t0;

    EXPECT_FALSE(tailer.running());
    EXPECT_LT(elapsed, 1000ms);
}

TEST_F(LogTailerTest, StopWithoutStartIsNoop) {
    LogTailer tailer(path_, [](std::string_view) {});
    // Should not crash or hang.
    tailer.stop();
    EXPECT_FALSE(tailer.running());
}

TEST_F(LogTailerTest, DestructorStopsThread) {
    std::atomic<bool> called{ false };
    {
        LogTailer tailer(path_, [&](std::string_view) { called = true; });
        tailer.start();
        std::this_thread::sleep_for(50ms);
    }  // destructor fires here — must not hang
    // If we reach this line the destructor joined successfully.
    SUCCEED();
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Empty lines and edge-content
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(LogTailerTest, DeliversEmptyLines) {
    std::vector<std::string> got;
    std::mutex               mtx;

    LogTailer tailer(path_, [&](std::string_view line) {
        std::lock_guard<std::mutex> lk(mtx);
        got.emplace_back(line);
    });
    tailer.start();
    std::this_thread::sleep_for(50ms);

    // Two empty lines (consecutive newlines) + one normal line.
    append_raw("\n\nhello\n");
    ASSERT_TRUE(wait_for(got, mtx, 3));
    tailer.stop();

    std::lock_guard<std::mutex> lk(mtx);
    ASSERT_EQ(got.size(), 3u);
    EXPECT_EQ(got[0], "");
    EXPECT_EQ(got[1], "");
    EXPECT_EQ(got[2], "hello");
}