cmake_minimum_required(VERSION 3.17)
project(dlads VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

add_compile_options(-Wall -Wextra -Wpedantic -Wno-unused-parameter)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
endif()

find_package(Threads REQUIRED)

# ── Third-party dependencies ──────────────────────────────────────────────────
include(FetchContent)

# nlohmann/json — header-only, used by alert_event
FetchContent_Declare(
  nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG        v3.11.3
  GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(nlohmann_json)

# GoogleTest
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        v1.14.0
  GIT_SHALLOW    TRUE
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# ── Include paths ─────────────────────────────────────────────────────────────
include_directories(include)

# ── dlads_core ────────────────────────────────────────────────────────────────
add_library(dlads_core STATIC
  src/log_tailer.cpp
  src/log_parser.cpp
  src/alert_event.cpp
)
target_include_directories(dlads_core PUBLIC include)
target_link_libraries(dlads_core PUBLIC
  Threads::Threads
  nlohmann_json::nlohmann_json
)

# ── Agent binary ──────────────────────────────────────────────────────────────
add_executable(dlads_agent src/agent_main.cpp)
target_link_libraries(dlads_agent PRIVATE dlads_core)

# ── Tests ─────────────────────────────────────────────────────────────────────
enable_testing()

add_executable(test_ring_buffer tests/test_ring_buffer.cpp)
target_include_directories(test_ring_buffer PRIVATE include)
target_link_libraries(test_ring_buffer PRIVATE GTest::gtest_main)
add_test(NAME RingBufferTests COMMAND test_ring_buffer)

add_executable(test_log_tailer tests/test_log_tailer.cpp)
target_link_libraries(test_log_tailer PRIVATE dlads_core GTest::gtest_main)
add_test(NAME LogTailerTests COMMAND test_log_tailer)

add_executable(test_log_parser tests/test_log_parser.cpp)
target_link_libraries(test_log_parser PRIVATE dlads_core GTest::gtest_main)
add_test(NAME LogParserTests COMMAND test_log_parser)

add_executable(test_alert_event tests/test_alert_event.cpp)
target_link_libraries(test_alert_event PRIVATE dlads_core GTest::gtest_main)
add_test(NAME AlertEventTests COMMAND test_alert_event)