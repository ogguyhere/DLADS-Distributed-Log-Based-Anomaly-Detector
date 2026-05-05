cmake_minimum_required(VERSION 3.17)
project(dlads VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

add_compile_options(-Wall -Wextra -Wpedantic -Wno-unused-parameter -Wno-unused-function)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
endif()

find_package(Threads REQUIRED)

# nlohmann/json
find_package(nlohmann_json QUIET)
if(NOT nlohmann_json_FOUND)
  add_library(nlohmann_json INTERFACE)
  target_include_directories(nlohmann_json INTERFACE ${CMAKE_SOURCE_DIR}/include)
  add_library(nlohmann_json::nlohmann_json ALIAS nlohmann_json)
endif()

# ZeroMQ
find_package(PkgConfig REQUIRED)
pkg_check_modules(ZMQ REQUIRED libzmq)

# cppzmq (header-only)
add_library(cppzmq INTERFACE)
target_include_directories(cppzmq INTERFACE ${CMAKE_SOURCE_DIR}/include)

# GoogleTest
find_package(GTest REQUIRED)

# Include paths (modern CMake already handles this via targets, but keeping for safety)
include_directories(include)

# ─────────────────────────────────────────────
# Core library
# ─────────────────────────────────────────────
add_library(dlads_core STATIC
  src/log_tailer.cpp
  src/log_parser.cpp
  src/alert_event.cpp
  src/rule_engine.cpp
)

target_include_directories(dlads_core PUBLIC include)

target_link_libraries(dlads_core PUBLIC
  Threads::Threads
  nlohmann_json::nlohmann_json
  ${ZMQ_LIBRARIES}
  cppzmq
)

# ─────────────────────────────────────────────
# Agent binary
# ─────────────────────────────────────────────
add_executable(dlads_agent src/agent_main.cpp)

target_link_libraries(dlads_agent PRIVATE dlads_core)

# ─────────────────────────────────────────────
# Subscriber binary
# ─────────────────────────────────────────────
add_executable(dlads_subscriber src/subscriber.cpp)

target_link_libraries(dlads_subscriber PRIVATE dlads_core ${ZMQ_LIBRARIES} cppzmq)


# ─────────────────────────────────────────────
# SQLite 
# ─────────────────────────────────────────────

find_package(SQLite3 REQUIRED)

# Coordinator binary (Person B - Final I)
add_executable(dlads_coordinator src/coordinator.cpp)
target_include_directories(dlads_coordinator PRIVATE include)
target_link_libraries(dlads_coordinator PRIVATE
  dlads_core
  ${ZMQ_LIBRARIES}
  cppzmq
  SQLite3::SQLite3
  Threads::Threads
)


# ─────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────
enable_testing()

add_executable(test_ring_buffer tests/test_ring_buffer.cpp)
target_link_libraries(test_ring_buffer PRIVATE dlads_core GTest::gtest_main)
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

add_executable(test_zscore tests/test_zscore.cpp)
target_link_libraries(test_zscore PRIVATE dlads_core GTest::gtest_main)
add_test(NAME ZScoreTests COMMAND test_zscore)

add_executable(test_rule_engine tests/test_rule_engine.cpp)
target_link_libraries(test_rule_engine PRIVATE dlads_core GTest::gtest_main)
add_test(NAME RuleEngineTests COMMAND test_rule_engine)