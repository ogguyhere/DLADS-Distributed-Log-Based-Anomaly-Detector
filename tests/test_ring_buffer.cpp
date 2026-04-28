// this file verifies if RingBuffer works in every important scenario:
// - Normal usage
// - Overflow
// - Clearing
// - Different data types
// - Multithreading
// - Edge cases


#include "dlads/ring_buffer.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <numeric>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

using namespace dlads;

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Push integers [first, last) into buf. */
template <typename Buf>
static void push_range(Buf& buf, int first, int last) {
    for (int i = first; i < last; ++i) buf.push(i);
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Static properties
// ─────────────────────────────────────────────────────────────────────────────

TEST(RingBufferStatic, CapacityIsCorrect) {
    RingBuffer<int, 8> buf;
    EXPECT_EQ(buf.capacity(), 8u);
}

TEST(RingBufferStatic, StartsEmpty) {
    RingBuffer<int, 4> buf;
    EXPECT_EQ(buf.size(), 0u);
    EXPECT_TRUE(buf.empty());
    EXPECT_FALSE(buf.full());
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Under-fill: N < capacity
// ─────────────────────────────────────────────────────────────────────────────

TEST(RingBufferUnderFill, SizeTracksCorrectly) {
    RingBuffer<int, 10> buf;
    for (int i = 0; i < 7; ++i) {
        buf.push(i);
        EXPECT_EQ(buf.size(), static_cast<std::size_t>(i + 1));
    }
    EXPECT_FALSE(buf.full());
}

TEST(RingBufferUnderFill, SnapshotIsInInsertionOrder) {
    RingBuffer<int, 10> buf;
    push_range(buf, 0, 7);   // 0..6

    auto snap = buf.snapshot();

    ASSERT_EQ(snap.size(), 7u);
    for (int i = 0; i < 7; ++i) {
        EXPECT_EQ(snap[i], i) << "mismatch at index " << i;
    }
}

TEST(RingBufferUnderFill, SnapshotOldestFirst) {
    RingBuffer<int, 5> buf;
    buf.push(10);
    buf.push(20);
    buf.push(30);

    auto snap = buf.snapshot();
    EXPECT_EQ(snap[0], 10);
    EXPECT_EQ(snap[1], 20);
    EXPECT_EQ(snap[2], 30);
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Over-fill: N > capacity  →  only latest Cap items survive
// ─────────────────────────────────────────────────────────────────────────────

TEST(RingBufferOverFill, SizeNeverExceedsCapacity) {
    RingBuffer<int, 5> buf;
    for (int i = 0; i < 20; ++i) {
        buf.push(i);
        EXPECT_LE(buf.size(), buf.capacity());
    }
    EXPECT_EQ(buf.size(), buf.capacity());
    EXPECT_TRUE(buf.full());
}

TEST(RingBufferOverFill, RetainsOnlyNewestElements) {
    // Capacity = 5, push 12 items (0..11).
    // Survivors must be the last 5: {7, 8, 9, 10, 11}.
    RingBuffer<int, 5> buf;
    push_range(buf, 0, 12);

    auto snap = buf.snapshot();
    ASSERT_EQ(snap.size(), 5u);

    std::vector<int> expected = {7, 8, 9, 10, 11};
    EXPECT_EQ(snap, expected);
}

TEST(RingBufferOverFill, SnapshotOrderAfterWrap) {
    // Capacity = 4. Push 6 items → wrap around.
    // Survivors: {2, 3, 4, 5}  oldest-first.
    RingBuffer<int, 4> buf;
    push_range(buf, 0, 6);

    auto snap = buf.snapshot();
    ASSERT_EQ(snap.size(), 4u);
    EXPECT_EQ(snap[0], 2);
    EXPECT_EQ(snap[1], 3);
    EXPECT_EQ(snap[2], 4);
    EXPECT_EQ(snap[3], 5);
}

TEST(RingBufferOverFill, ExactFillThenOnMore) {
    // Fill exactly to capacity, then push one more.
    RingBuffer<int, 3> buf;
    buf.push(1); buf.push(2); buf.push(3);  // full
    buf.push(4);                             // evicts 1

    auto snap = buf.snapshot();
    ASSERT_EQ(snap.size(), 3u);
    EXPECT_EQ(snap[0], 2);
    EXPECT_EQ(snap[1], 3);
    EXPECT_EQ(snap[2], 4);
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Clear
// ─────────────────────────────────────────────────────────────────────────────

TEST(RingBufferClear, ClearResetsState) {
    RingBuffer<int, 5> buf;
    push_range(buf, 0, 5);
    EXPECT_TRUE(buf.full());

    buf.clear();
    EXPECT_EQ(buf.size(), 0u);
    EXPECT_TRUE(buf.empty());
    EXPECT_TRUE(buf.snapshot().empty());
}

TEST(RingBufferClear, PushAfterClearWorks) {
    RingBuffer<int, 4> buf;
    push_range(buf, 100, 104);
    buf.clear();
    push_range(buf, 0, 3);

    auto snap = buf.snapshot();
    ASSERT_EQ(snap.size(), 3u);
    EXPECT_EQ(snap[0], 0);
    EXPECT_EQ(snap[1], 1);
    EXPECT_EQ(snap[2], 2);
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Non-trivial types (strings)
// ─────────────────────────────────────────────────────────────────────────────

TEST(RingBufferTypes, WorksWithStrings) {
    RingBuffer<std::string, 4> buf;
    buf.push("alpha");
    buf.push("beta");
    buf.push("gamma");
    buf.push("delta");
    buf.push("epsilon");  // evicts "alpha"

    auto snap = buf.snapshot();
    ASSERT_EQ(snap.size(), 4u);
    EXPECT_EQ(snap[0], "beta");
    EXPECT_EQ(snap[3], "epsilon");
}

TEST(RingBufferTypes, MoveSemantics) {
    RingBuffer<std::vector<int>, 3> buf;
    std::vector<int> v = {1, 2, 3};
    buf.push(std::move(v));
    EXPECT_TRUE(v.empty());  // moved-from

    auto snap = buf.snapshot();
    ASSERT_EQ(snap.size(), 1u);
    EXPECT_EQ((snap[0]), (std::vector<int>{1, 2, 3}));
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Concurrent pushes from two threads — no crash, size ≤ capacity
// ─────────────────────────────────────────────────────────────────────────────

TEST(RingBufferConcurrency, TwoProducersNoCrash) {
    constexpr int PUSHES_PER_THREAD = 10'000;
    RingBuffer<int, 512> buf;

    auto worker = [&](int base) {
        for (int i = 0; i < PUSHES_PER_THREAD; ++i) buf.push(base + i);
    };

    std::thread t1(worker, 0);
    std::thread t2(worker, 100'000);
    t1.join();
    t2.join();

    EXPECT_LE(buf.size(), buf.capacity());
    EXPECT_EQ(buf.size(), buf.capacity());
}

TEST(RingBufferConcurrency, SnapshotUnderConcurrentPush) {
    // Verify snapshot() does not crash or return a partially-updated vector
    // while another thread is continuously pushing.
    RingBuffer<int, 64> buf;
    std::atomic<bool> stop{ false };

    std::thread producer([&] {
        int v = 0;
        while (!stop.load(std::memory_order_relaxed)) buf.push(v++);
    });

    for (int i = 0; i < 500; ++i) {
        auto snap = buf.snapshot();
        // All we can assert here: snapshot is self-consistent in size.
        EXPECT_LE(snap.size(), buf.capacity());
    }

    stop.store(true);
    producer.join();
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Snapshot returns a copy — mutating it does not affect the buffer
// ─────────────────────────────────────────────────────────────────────────────

TEST(RingBufferSnapshot, IsADeepCopy) {
    RingBuffer<int, 4> buf;
    push_range(buf, 1, 4);

    auto snap = buf.snapshot();
    snap[0] = 9999;  // mutate the copy

    auto snap2 = buf.snapshot();
    EXPECT_EQ(snap2[0], 1);  // original untouched
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Edge cases
// ─────────────────────────────────────────────────────────────────────────────

TEST(RingBufferEdge, CapacityOfOne) {
    RingBuffer<int, 1> buf;
    buf.push(42);
    EXPECT_EQ(buf.size(), 1u);
    EXPECT_TRUE(buf.full());

    buf.push(99);  // evicts 42
    auto snap = buf.snapshot();
    ASSERT_EQ(snap.size(), 1u);
    EXPECT_EQ(snap[0], 99);
}

TEST(RingBufferEdge, PushExactlyCapacityTimes) {
    constexpr std::size_t CAP = 8;
    RingBuffer<int, CAP> buf;
    push_range(buf, 0, static_cast<int>(CAP));

    EXPECT_TRUE(buf.full());
    auto snap = buf.snapshot();
    ASSERT_EQ(snap.size(), CAP);
    for (std::size_t i = 0; i < CAP; ++i) {
        EXPECT_EQ(snap[i], static_cast<int>(i));
    }
}

TEST(RingBufferEdge, MultipleWraparounds) {
    // Push 3× capacity and verify only the last Cap elements survive.
    RingBuffer<int, 6> buf;
    push_range(buf, 0, 18);  // 3 × 6

    auto snap = buf.snapshot();
    ASSERT_EQ(snap.size(), 6u);
    EXPECT_EQ(snap[0], 12);
    EXPECT_EQ(snap[5], 17);
}