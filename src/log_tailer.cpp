#include "dlads/log_tailer.hpp"

#include <cerrno>
#include <cstring>
#include <iostream>

#include <fcntl.h>
#include <poll.h>
#include <sys/inotify.h>
#include <unistd.h>

namespace dlads {

// ── inotify event buffer ──────────────────────────────────────────────────────
// NAME_MAX is a runtime constant on some platforms so we cannot use it in a
// constexpr.  Use a plain enum instead — 4 KiB is more than enough for several
// events at once (each inotify_event is 16 bytes + optional name).
enum : std::size_t { INOTIFY_BUF = 4096 };

// Read buffer for file content.
static constexpr std::size_t READ_BUF = 65536;

// ── Constructor / destructor ──────────────────────────────────────────────────

LogTailer::LogTailer(std::string path, LineCallback cb, int poll_interval_ms)
    : path_(std::move(path))
    , cb_(std::move(cb))
    , poll_interval_ms_(poll_interval_ms)
{}

LogTailer::~LogTailer() {
    stop();
}

// ── Public API ────────────────────────────────────────────────────────────────

void LogTailer::start() {
    if (running_.load(std::memory_order_acquire)) return;
    stop_.store(false, std::memory_order_release);
    thread_  = std::thread(&LogTailer::run, this);
}

void LogTailer::stop() {
    stop_.store(true, std::memory_order_release);
    if (thread_.joinable()) thread_.join();
}

// ── Private helpers ───────────────────────────────────────────────────────────

int LogTailer::open_file(bool seek_to_end) const {
    int fd = ::open(path_.c_str(), O_RDONLY | O_NONBLOCK);
    if (fd == -1) return -1;
    if (seek_to_end) ::lseek(fd, 0, SEEK_END);
    return fd;
}

void LogTailer::drain(int file_fd) {
    char buf[READ_BUF];
    while (true) {
        ssize_t n = ::read(file_fd, buf, sizeof(buf));
        if (n <= 0) break;          // EAGAIN or EOF — nothing more right now

        const char* p   = buf;
        const char* end = buf + n;

        while (p < end) {
            const char* nl = static_cast<const char*>(
                std::memchr(p, '\n', static_cast<std::size_t>(end - p)));

            if (nl) {
                // Complete line: partial_ prefix + new chunk up to (not
                // including) the newline.
                partial_.append(p, nl);
                if (cb_) cb_(partial_);
                partial_.clear();
                p = nl + 1;
            } else {
                // No newline yet — buffer the remainder.
                partial_.append(p, end);
                break;
            }
        }
    }
}

// ── Background thread ─────────────────────────────────────────────────────────

void LogTailer::run() {
    running_.store(true, std::memory_order_release);

    // ── Set up inotify ────────────────────────────────────────────────────────
    int ifd = ::inotify_init1(IN_NONBLOCK);
    if (ifd == -1) {
        std::cerr << "[LogTailer] inotify_init1 failed: "
                  << std::strerror(errno) << "\n";
        running_.store(false, std::memory_order_release);
        return;
    }

    // ── Open the target file ──────────────────────────────────────────────────
    int file_fd = -1;
    int wd      = -1;

    auto attach = [&](bool seek_end) -> bool {
        file_fd = open_file(seek_end);
        if (file_fd == -1) return false;
        wd = ::inotify_add_watch(ifd, path_.c_str(),
                                 IN_MODIFY | IN_MOVE_SELF | IN_DELETE_SELF);
        if (wd == -1) {
            std::cerr << "[LogTailer] inotify_add_watch failed: "
                      << std::strerror(errno) << "\n";
            ::close(file_fd);
            file_fd = -1;
            return false;
        }
        return true;
    };

    // Initial open: seek to EOF so we skip existing content.
    while (!stop_.load(std::memory_order_acquire) && !attach(/*seek_end=*/true)) {
        std::cerr << "[LogTailer] cannot open '" << path_
                  << "', retrying in " << poll_interval_ms_ << " ms\n";
        std::this_thread::sleep_for(
            std::chrono::milliseconds(poll_interval_ms_));
    }

    // ── Poll loop ─────────────────────────────────────────────────────────────
    char ibuf[INOTIFY_BUF];

    while (!stop_.load(std::memory_order_acquire)) {
        if (file_fd == -1) {
            // Re-attach after rotation.
            if (!attach(/*seek_end=*/false)) {
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(poll_interval_ms_));
                continue;
            }
        }

        pollfd pfd{ ifd, POLLIN, 0 };
        int ret = ::poll(&pfd, 1, poll_interval_ms_);

        if (ret < 0) {
            if (errno == EINTR) continue;
            std::cerr << "[LogTailer] poll error: " << std::strerror(errno) << "\n";
            break;
        }

        if (ret == 0) continue;   // timeout — check stop_ and loop

        // Drain inotify events.
        ssize_t len = ::read(ifd, ibuf, sizeof(ibuf));
        if (len <= 0) continue;

        bool rotated = false;
        for (char* ptr = ibuf; ptr < ibuf + len; ) {
            auto* ev = reinterpret_cast<inotify_event*>(ptr);
            ptr += sizeof(inotify_event) + ev->len;

            if (ev->mask & IN_MODIFY) {
                drain(file_fd);
            }
            if (ev->mask & (IN_MOVE_SELF | IN_DELETE_SELF)) {
                // Flush whatever is buffered before treating as rotated.
                drain(file_fd);
                rotated = true;
            }
        }

        if (rotated) {
            ::inotify_rm_watch(ifd, wd);
            wd = -1;
            ::close(file_fd);
            file_fd = -1;
            partial_.clear();
        }
    }

    // ── Cleanup ───────────────────────────────────────────────────────────────
    if (file_fd != -1) ::close(file_fd);
    ::close(ifd);
    running_.store(false, std::memory_order_release);
}

}  // namespace dlads