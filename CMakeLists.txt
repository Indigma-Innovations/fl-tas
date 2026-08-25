cmake_minimum_required(VERSION 3.16)
project(asyncfed_tas CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

include(FetchContent)

# Crow
FetchContent_Declare(
  crow
  GIT_REPOSITORY https://github.com/CrowCpp/Crow.git
  GIT_TAG v1.3.0
)
FetchContent_MakeAvailable(crow)

# nlohmann/json
FetchContent_Declare(
  nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.11.3
)
FetchContent_MakeAvailable(nlohmann_json)

# Define target first
add_executable(tas_server
  src/main.cpp
  src/http_server.cpp
  src/key_store.cpp
  src/crypto.cpp
  src/sessions.cpp
  src/aggregation_bridge.cpp
)

# Include dirs
target_include_directories(tas_server PRIVATE
  include
  ${SODIUM_INCLUDE_DIRS}
  ${crow_SOURCE_DIR}/include
)

# Base libs
target_link_libraries(tas_server PRIVATE
  Threads::Threads
  OpenSSL::SSL OpenSSL::Crypto
  CURL::libcurl
  ${SODIUM_LIBRARIES}
  nlohmann_json::nlohmann_json
)

# Crow target name varies; link if present
if (TARGET crow)
  target_link_libraries(tas_server PRIVATE crow)
elseif (TARGET Crow::Crow)
  target_link_libraries(tas_server PRIVATE Crow::Crow)
endif()

target_compile_options(tas_server PRIVATE -Wall -Wextra -Wpedantic)

# Optional SEAL
option(TAS_ENABLE_SEAL "Enable Microsoft SEAL (CKKS/FHE)" OFF)

if (TAS_ENABLE_SEAL)
  set(SEAL_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
  set(SEAL_BUILD_TESTS OFF CACHE BOOL "" FORCE)
  set(SEAL_BUILD_BENCH OFF CACHE BOOL "" FORCE)

  FetchContent_Declare(
    seal
    URL https://github.com/microsoft/SEAL/archive/refs/tags/v4.1.2.tar.gz
  )
  FetchContent_MakeAvailable(seal)

  if (TARGET SEAL::seal)
    target_link_libraries(tas_server PRIVATE SEAL::seal)
  elseif (TARGET seal)
    target_link_libraries(tas_server PRIVATE seal)
  else()
    message(FATAL_ERROR "SEAL target not found after FetchContent.")
  endif()

  target_compile_definitions(tas_server PRIVATE TAS_ENABLE_SEAL=1)

  target_sources(tas_server PRIVATE src/fhe_store.cpp)
endif()
