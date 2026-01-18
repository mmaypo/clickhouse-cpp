cmake_minimum_required(VERSION 3.12)
project(application-example)

set(CMAKE_CXX_STANDARD 17)

# Ensure OpenSSL is available (Ubuntu: sudo apt-get install -y libssl-dev)
find_package(OpenSSL REQUIRED)

# IMPORTANT: must be CACHE and set BEFORE add_subdirectory()
set(WITH_OPENSSL ON CACHE BOOL "Enable OpenSSL support in clickhouse-cpp" FORCE)

add_subdirectory(contribs/clickhouse-cpp)

add_executable(${PROJECT_NAME} app.cpp)

# Usually you do NOT need to add include dirs manually if you link the target,
# but keep yours if you rely on them.
# target_include_directories(${PROJECT_NAME} PRIVATE
#     contribs/clickhouse-cpp/
#     contribs/clickhouse-cpp/contrib/absl
# )

target_link_libraries(${PROJECT_NAME} PRIVATE clickhouse-cpp-lib OpenSSL::SSL OpenSSL::Crypto)

