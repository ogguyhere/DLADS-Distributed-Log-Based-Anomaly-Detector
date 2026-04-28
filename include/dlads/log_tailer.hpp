#pragma once

#include <atomic>
#include <functional>
#include <string>
#include <thread>

namespace dlads {

/**
 * LogTailer
 *
 * Watches a single file for new appended lines using inotify and delivers
 * each complete line to a user-supplied callback on a background thread.
 *
 * Behaviour guarantees:
 *   - Only lines appended *after* start() is called are delivered (seeks
 *     to EOF on open, so existing content is skipped).
 *   - Incomplete lines (no trailing '\n' yet) are buffered internally and
 *     delivered as soon as the newline arrives.
 *   - Log rotation is handled: if the watched file is moved or deleted
 *     (IN_MOVE_SELF / IN_DELETE_SELF) the tailer re-opens the file at the
 *     same path and resets the read offset to 0.
 *   - stop() is safe to call from any thread and always joins cleanly.
 *
 * Thread safety:
 *   - start() / stop() must be called from the same thread.
 *   - The callback is invoked from the background thread; ensure it is
 *     thread-safe.
 *
 * Error handling:
 *   - If the file cannot be opened at start() time the worker thread logs
 *     to stderr and retries every poll_interval_ms milliseconds.
 *   - inotify / read errors are logged to stderr; the tailer continues.
 */
class LogTailer {
public:
    using LineCallback = std::function<void(std::string_view line)>;

    /**
     * @param path              Absolute or relative path to the file to tail.
     * @param cb                Called once per complete line (no '\n' included).
     * @param poll_interval_ms  How long (ms) to block on the inotify fd per
     *                          iteration.  Lower values reduce stop() latency.
     */
    explicit LogTailer(std::string        path,
                       LineCallback       cb,
                       int                poll_interval_ms = 100);

    ~LogTailer();

    // Non-copyable, non-movable.
    LogTailer(const LogTailer&)            = delete;
    LogTailer& operator=(const LogTailer&) = delete;
    LogTailer(LogTailer&&)                 = delete;
    LogTailer& operator=(LogTailer&&)      = delete;

    /** Spawn the background thread and begin tailing. */
    void start();

    /**
     * Signal the background thread to stop and block until it exits.
     * Safe to call even if start() was never called.
     */
    void stop();

    /** True between a successful start() and a stop(). */
    bool running() const noexcept { return running_.load(std::memory_order_acquire); }

private:
    // Entry point for the background thread.
    void run();

    // Open (or re-open) the target file.  Returns the fd or -1 on failure.
    // When seek_to_end is true the read position is placed at EOF.
    int open_file(bool seek_to_end) const;

    // Drain all bytes available from file_fd_ and dispatch complete lines.
    void drain(int file_fd);

    // ── Configuration ─────────────────────────────────────────────────────────
    std::string  path_;
    LineCallback cb_;
    int          poll_interval_ms_;

    // ── Threading ─────────────────────────────────────────────────────────────
    std::thread       thread_;
    std::atomic<bool> stop_{ false };
    std::atomic<bool> running_{ false };

    // ── Line assembly ─────────────────────────────────────────────────────────
    // Bytes read from the file that don't yet end with '\n'.
    std::string partial_;
};

}  // namespace dlads