cmake_minimum_required(VERSION 3.20)
project(pywechat_hook LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---------- Dependencies via FetchContent ----------
include(FetchContent)

# MinHook - lightweight API hooking library
FetchContent_Declare(
    minhook
    GIT_REPOSITORY https://github.com/TsudaKageyu/minhook.git
    GIT_TAG        master
)

# nlohmann/json - JSON for Modern C++
FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        v3.11.3
)

# spdlog - fast C++ logging library
FetchContent_Declare(
    spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG        v1.13.0
)

FetchContent_MakeAvailable(minhook nlohmann_json spdlog)

# ---------- DLL target ----------
add_library(pywechat_hook SHARED
    src/dllmain.cpp
    src/pipe_server.cpp
    src/sig_scanner.cpp
    src/sns_comment.cpp
    src/hook_manager.cpp
    src/version_check.cpp
    src/sns_moments_poc.cpp
)

target_include_directories(pywechat_hook PRIVATE src)

target_link_libraries(pywechat_hook PRIVATE
    minhook
    nlohmann_json::nlohmann_json
    spdlog::spdlog
    ole32
    user32
)

# Windows-specific: export nothing by default, DllMain is the entry point
set_target_properties(pywechat_hook PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    PREFIX ""
)

# Disable MSVC warnings for SEH in C++ code
if(MSVC)
    target_compile_options(pywechat_hook PRIVATE /EHa)
endif()
