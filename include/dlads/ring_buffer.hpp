#pragma once

#include <array>
#include <cstddef>
#include <mutex>
#include <vector>

namespace dlads {

/**
 * Thread-safe fixed-capacity circular ring buffer.
 *
 * Semantics:
 *   - push() overwrites the oldest entry when the buffer is full.
 *   - snapshot() returns a copy of all current entries in insertion order
 *     (oldest first, newest last).
 *   - All operations are O(1) except snapshot() which is O(N).
 *   - Zero heap allocation after construction.
 *
 * @tparam T    Element type.  Must be move-constructible.
 * @tparam Cap  Maximum number of elements stored simultaneously.
 *              Must be > 0.
 */
template <typename T, std::size_t Cap>
class RingBuffer {
    static_assert(Cap > 0, "RingBuffer capacity must be greater than zero");

public:
    RingBuffer() = default;

    // Non-copyable, non-movable — internal mutex makes this the right call.
    RingBuffer(const RingBuffer&)            = delete;
    RingBuffer& operator=(const RingBuffer&) = delete;
    RingBuffer(RingBuffer&&)                 = delete;
    RingBuffer& operator=(RingBuffer&&)      = delete;

    // ── Capacity ──────────────────────────────────────────────────────────────

    /** Maximum number of elements the buffer can hold. */
    static constexpr std::size_t capacity() noexcept { return Cap; }

    /** Current number of elements stored (0 … Cap). */
    std::size_t size() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return size_;
    }

    /** True iff size() == 0. */
    bool empty() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return size_ == 0;
    }

    /** True iff size() == Cap. */
    bool full() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return size_ == Cap;
    }

    // ── Mutation ──────────────────────────────────────────────────────────────

    /**
     * Push a new element into the buffer.
     *
     * If the buffer is already full the oldest element is silently
     * overwritten (overwrite-on-full semantics).
     *
     * @param value  Element to store (perfect-forwarded).
     */
    template <typename U>
    void push(U&& value) {
        std::lock_guard<std::mutex> lock(mutex_);
        storage_[head_] = std::forward<U>(value);
        head_           = next(head_);
        if (size_ < Cap) {
            ++size_;
        } else {
            // Buffer was full: tail must chase head to skip the overwritten slot.
            tail_ = next(tail_);
        }
    }

    /**
     * Remove all elements.  size() becomes 0 after this call.
     */
    void clear() noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        head_  = 0;
        tail_  = 0;
        size_  = 0;
    }

    // ── Observation ───────────────────────────────────────────────────────────

    /**
     * Return a snapshot of all current elements in insertion order
     * (oldest first, newest last).
     *
     * The copy is taken under the internal lock so the result is
     * consistent even under concurrent pushes.
     */
    std::vector<T> snapshot() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<T> out;
        out.reserve(size_);
        for (std::size_t i = 0; i < size_; ++i) {
            out.push_back(storage_[(tail_ + i) % Cap]);
        }
        return out;
    }

private:
    // ── Internal helpers ──────────────────────────────────────────────────────

    static constexpr std::size_t next(std::size_t idx) noexcept {
        return (idx + 1) % Cap;
    }

    // ── Data members ──────────────────────────────────────────────────────────

    mutable std::mutex             mutex_;
    std::array<T, Cap>             storage_{};

    // head_: next write position.
    // tail_: position of the oldest element (valid when size_ > 0).
    std::size_t                    head_{ 0 };
    std::size_t                    tail_{ 0 };
    std::size_t                    size_{ 0 };
};

}  // namespace dlads