cmake_minimum_required(VERSION 3.21)

project(9ns LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "9ns builds for Windows only. It uses Winsock, WinHTTP and the Windows DNS settings API.")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_AUTORCC ON)

find_package(Qt6 6.5 REQUIRED COMPONENTS Widgets Svg)
find_package(OpenSSL REQUIRED)

# libsodium: vcpkg ships a CMake package. MSYS2 and other MinGW builds ship only
# headers, an import library and a .pc file, so fall back to a plain lookup.
find_package(unofficial-sodium CONFIG QUIET)
if(TARGET unofficial-sodium::sodium)
    set(NS9_SODIUM_TARGET unofficial-sodium::sodium)
else()
    find_path(SODIUM_INCLUDE_DIR sodium.h REQUIRED)
    find_library(SODIUM_LIBRARY NAMES sodium libsodium REQUIRED)
    add_library(9ns_sodium UNKNOWN IMPORTED)
    set_target_properties(9ns_sodium PROPERTIES
        IMPORTED_LOCATION "${SODIUM_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${SODIUM_INCLUDE_DIR}")
    set(NS9_SODIUM_TARGET 9ns_sodium)
endif()

# nlohmann_json is header-only. Use an installed copy if CMake can see one,
# otherwise download the official release archive at configure time.
find_package(nlohmann_json CONFIG QUIET)
if(NOT TARGET nlohmann_json::nlohmann_json)
    include(FetchContent)
    FetchContent_Declare(nlohmann_json
        URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
        URL_HASH SHA256=d6c65aca6b1ed68e7a182f4757257b107ae403032760ed6ef121c9d55e81757d)
    FetchContent_MakeAvailable(nlohmann_json)
endif()

qt_standard_project_setup()

qt_add_executable(9ns WIN32
    src/core/Cache.cpp
    src/core/Config.cpp
    src/core/DnsMessage.cpp
    src/core/DnsSec.cpp
    src/core/Engine.cpp
    src/core/Logger.cpp
    src/core/Pool.cpp
    src/core/ProtectedDirectory.cpp
    src/core/Proxy.cpp
    src/core/Resolver.cpp
    src/core/Rules.cpp
    src/core/SystemDns.cpp
    src/core/WindowsService.cpp
    src/transports/DnsCryptUpstream.cpp
    src/transports/DoqUpstream.cpp
    src/transports/DotUpstream.cpp
    src/transports/OdohUpstream.cpp
    src/transports/Stamp.cpp
    src/transports/Upstream.cpp
    src/web/PublicResolversLoader.cpp
    src/ui/ConfigSession.cpp
    src/ui/Donate.cpp
    src/ui/MainWindow.cpp
    src/ui/PoolDialog.cpp
    src/ui/PublicResolverImport.cpp
    src/ui/PublicResolversDialog.cpp
    src/ui/PublicResolversProduction.cpp
    src/ui/QueryDetailsDialog.cpp
    src/ui/QueryLogFilterProxyModel.cpp
    src/ui/QueryLogModel.cpp
    src/ui/ResolverJobs.cpp
    src/ui/RuleDialog.cpp
    src/ui/ServerDialog.cpp
    src/ui/Theme.cpp
    src/ui/WizardDialog.cpp
    src/ui/pages/OverviewPage.cpp
    src/ui/pages/QueryLogPage.cpp
    src/ui/pages/RulesPage.cpp
    src/ui/pages/ServersPoolsPage.cpp
    src/ui/pages/SettingsPage.cpp
    src/ui/pages/SystemLogPage.cpp
    src/main.cpp
    src/resources/resources.qrc
)

target_include_directories(9ns PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

# The manifest asks for administrator rights (port 53 and adapter DNS need them).
# MSVC merges a .manifest source itself, and a second copy from an .rc file would
# fail with a duplicate-resource error. MinGW needs the .rc file.
if(MSVC)
    target_sources(9ns PRIVATE src/resources/app.manifest)
else()
    target_sources(9ns PRIVATE src/resources/app.rc)
endif()

target_compile_definitions(9ns PRIVATE UNICODE _UNICODE NOMINMAX)

target_link_libraries(9ns PRIVATE
    Qt6::Widgets
    Qt6::Svg
    ${NS9_SODIUM_TARGET}
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    ws2_32
    winhttp
    advapi32
    iphlpapi
    shell32
    crypt32
    secur32
)

# Opt-in offline regression tests. Release builds keep the dependency set above;
# Qt6::Test is only looked up by tests/CMakeLists.txt.
option(BUILD_TESTING "Build the offline regression tests" OFF)
if(BUILD_TESTING)
    include(CTest)
    enable_testing()
    add_subdirectory(tests)
endif()
