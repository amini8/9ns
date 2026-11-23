# Offline regression tests. Linked only when BUILD_TESTING is ON.
# These tests must never touch ProgramData, real adapters, the registry,
# Windows services or the network: they use QTemporaryDir and fakes only.

find_package(Qt6 6.5 REQUIRED COMPONENTS Test)

# --- Config: parsing, validation, round-trip and legacy NextDNS rejection ---
add_executable(test_config test_config.cpp
    ${CMAKE_SOURCE_DIR}/src/core/Config.cpp
    ${CMAKE_SOURCE_DIR}/src/transports/Stamp.cpp
)
target_include_directories(test_config PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_definitions(test_config PRIVATE NS9_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
target_link_libraries(test_config PRIVATE Qt6::Test nlohmann_json::nlohmann_json)
add_test(NAME test_config COMMAND test_config)

# --- ProxyProtocol: SOCKS5/SOCKS4a/HTTP CONNECT framing, pure and socket-free ---
add_executable(test_proxyprotocol test_proxyprotocol.cpp
    ${CMAKE_SOURCE_DIR}/src/core/ProxyProtocol.cpp
)
target_include_directories(test_proxyprotocol PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_proxyprotocol PRIVATE Qt6::Test)
add_test(NAME test_proxyprotocol COMMAND test_proxyprotocol)
set_tests_properties(test_proxyprotocol PROPERTIES TIMEOUT 30)

# --- ConfigSession: draft/saved/running semantics, dirty tracking ---
add_executable(test_configsession test_configsession.cpp
    ${CMAKE_SOURCE_DIR}/src/core/Config.cpp
    ${CMAKE_SOURCE_DIR}/src/transports/Stamp.cpp
    ${CMAKE_SOURCE_DIR}/src/ui/ConfigSession.cpp
)
target_include_directories(test_configsession PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_configsession PRIVATE Qt6::Test nlohmann_json::nlohmann_json)
add_test(NAME test_configsession COMMAND test_configsession)

# --- ResolverJobs: dispatcher lifetime, cancellation, result routing ---
add_executable(test_jobs test_jobs.cpp
    ${CMAKE_SOURCE_DIR}/src/core/Config.cpp
    ${CMAKE_SOURCE_DIR}/src/transports/Stamp.cpp
    ${CMAKE_SOURCE_DIR}/src/ui/ResolverJobs.cpp
)
target_include_directories(test_jobs PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_jobs PRIVATE Qt6::Test nlohmann_json::nlohmann_json)
add_test(NAME test_jobs COMMAND test_jobs)

# --- QueryLogModel: timestamps, eviction, filters, snapshots ---
add_executable(test_querylog test_querylog.cpp
    ${CMAKE_SOURCE_DIR}/src/core/Config.cpp
    ${CMAKE_SOURCE_DIR}/src/transports/Stamp.cpp
    ${CMAKE_SOURCE_DIR}/src/ui/QueryLogModel.cpp
    ${CMAKE_SOURCE_DIR}/src/ui/QueryLogFilterProxyModel.cpp
)
target_include_directories(test_querylog PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_querylog PRIVATE Qt6::Test Qt6::Widgets nlohmann_json::nlohmann_json)
add_test(NAME test_querylog COMMAND test_querylog)

# --- Dialog ordering and candidate validation (pool/rule/server round-trip) ---
add_executable(test_dialogs test_dialogs.cpp
    ${CMAKE_SOURCE_DIR}/src/core/Config.cpp
    ${CMAKE_SOURCE_DIR}/src/transports/Stamp.cpp
)
target_include_directories(test_dialogs PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_dialogs PRIVATE Qt6::Test nlohmann_json::nlohmann_json)
add_test(NAME test_dialogs COMMAND test_dialogs)

# Native page interactions only: no Engine, MainWindow or system-operation sources.
add_executable(test_querypage test_querypage.cpp
    ${CMAKE_SOURCE_DIR}/src/ui/QueryLogModel.cpp
    ${CMAKE_SOURCE_DIR}/src/ui/QueryLogFilterProxyModel.cpp
    ${CMAKE_SOURCE_DIR}/src/ui/Theme.cpp
    ${CMAKE_SOURCE_DIR}/src/ui/pages/QueryLogPage.cpp
)
target_include_directories(test_querypage PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_definitions(test_querypage PRIVATE UNICODE _UNICODE NOMINMAX)
target_link_libraries(test_querypage PRIVATE Qt6::Test Qt6::Widgets)
add_test(NAME test_querypage COMMAND test_querypage)
set_tests_properties(test_querypage PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen" TIMEOUT 30)

add_executable(test_settingspages test_settingspages.cpp
    ${CMAKE_SOURCE_DIR}/src/ui/Theme.cpp
    ${CMAKE_SOURCE_DIR}/src/ui/pages/OverviewPage.cpp
    ${CMAKE_SOURCE_DIR}/src/ui/pages/RulesPage.cpp
    ${CMAKE_SOURCE_DIR}/src/ui/pages/ServersPoolsPage.cpp
    ${CMAKE_SOURCE_DIR}/src/ui/pages/SettingsPage.cpp
    ${CMAKE_SOURCE_DIR}/src/ui/pages/SystemLogPage.cpp
)
target_include_directories(test_settingspages PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_definitions(test_settingspages PRIVATE UNICODE _UNICODE NOMINMAX)
target_link_libraries(test_settingspages PRIVATE Qt6::Test Qt6::Widgets)
add_test(NAME test_settingspages COMMAND test_settingspages)
set_tests_properties(test_settingspages PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen" TIMEOUT 30)

# Rule editor uses fixture interface data: no SystemDns implementation or adapter access.
add_executable(test_ruledialog test_ruledialog.cpp
    ${CMAKE_SOURCE_DIR}/src/ui/RuleDialog.cpp
)
target_include_directories(test_ruledialog PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_definitions(test_ruledialog PRIVATE UNICODE _UNICODE NOMINMAX)
target_link_libraries(test_ruledialog PRIVATE Qt6::Test Qt6::Widgets)
add_test(NAME test_ruledialog COMMAND test_ruledialog)
set_tests_properties(test_ruledialog PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen" TIMEOUT 30)

# Protocol framing and hosts parsing use fake I/O / temporary files only.
add_executable(test_doq test_doq.cpp
    ${CMAKE_SOURCE_DIR}/src/core/DnsMessage.cpp
)
target_include_directories(test_doq PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_definitions(test_doq PRIVATE UNICODE _UNICODE NOMINMAX)
target_link_libraries(test_doq PRIVATE Qt6::Test ws2_32)
add_test(NAME test_doq COMMAND test_doq)
set_tests_properties(test_doq PROPERTIES TIMEOUT 30)

add_executable(test_rules test_rules.cpp
    ${CMAKE_SOURCE_DIR}/src/core/Rules.cpp
)
target_include_directories(test_rules PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_definitions(test_rules PRIVATE UNICODE _UNICODE NOMINMAX)
target_link_libraries(test_rules PRIVATE Qt6::Test ws2_32)
add_test(NAME test_rules COMMAND test_rules)
set_tests_properties(test_rules PROPERTIES TIMEOUT 30)

# Resolver list/download/cache/import seams use fake I/O and explicit temp paths.
add_executable(test_publicresolvers test_publicresolvers.cpp
    ${CMAKE_SOURCE_DIR}/src/core/Config.cpp
    ${CMAKE_SOURCE_DIR}/src/transports/Stamp.cpp
    ${CMAKE_SOURCE_DIR}/src/web/PublicResolversLoader.cpp
    ${CMAKE_SOURCE_DIR}/src/ui/PublicResolverImport.cpp
)
target_include_directories(test_publicresolvers PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_definitions(test_publicresolvers PRIVATE UNICODE _UNICODE NOMINMAX)
target_link_libraries(test_publicresolvers PRIVATE Qt6::Test nlohmann_json::nlohmann_json winhttp)
add_test(NAME test_publicresolvers COMMAND test_publicresolvers)
set_tests_properties(test_publicresolvers PROPERTIES TIMEOUT 30)

# Actual browser widgets, without production transports or the default loader path.
add_executable(test_publicresolversdialog test_publicresolversdialog.cpp
    ${CMAKE_SOURCE_DIR}/src/core/Config.cpp
    ${CMAKE_SOURCE_DIR}/src/transports/Stamp.cpp
    ${CMAKE_SOURCE_DIR}/src/web/PublicResolversLoader.cpp
    ${CMAKE_SOURCE_DIR}/src/ui/Donate.cpp
    ${CMAKE_SOURCE_DIR}/src/ui/PublicResolverImport.cpp
    ${CMAKE_SOURCE_DIR}/src/ui/PublicResolversDialog.cpp
    ${CMAKE_SOURCE_DIR}/src/ui/ResolverJobs.cpp
)
target_include_directories(test_publicresolversdialog PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_definitions(test_publicresolversdialog PRIVATE UNICODE _UNICODE NOMINMAX)
target_link_libraries(test_publicresolversdialog PRIVATE Qt6::Test Qt6::Widgets nlohmann_json::nlohmann_json winhttp)
add_test(NAME test_publicresolversdialog COMMAND test_publicresolversdialog)
set_tests_properties(test_publicresolversdialog PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen" TIMEOUT 30)

# Synthetic DNS answer sizing / response validation. Pure wire helpers only.
add_executable(test_dnsmessages test_dnsmessages.cpp
    ${CMAKE_SOURCE_DIR}/src/core/DnsMessage.cpp
)
target_include_directories(test_dnsmessages PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_definitions(test_dnsmessages PRIVATE UNICODE _UNICODE NOMINMAX)
target_link_libraries(test_dnsmessages PRIVATE Qt6::Test ws2_32)
add_test(NAME test_dnsmessages COMMAND test_dnsmessages)
set_tests_properties(test_dnsmessages PROPERTIES TIMEOUT 30)

# Reply-cache context separation and validation provenance.
add_executable(test_cache test_cache.cpp
    ${CMAKE_SOURCE_DIR}/src/core/Cache.cpp
    ${CMAKE_SOURCE_DIR}/src/core/DnsMessage.cpp
    ${CMAKE_SOURCE_DIR}/src/core/DnsSec.cpp
)
target_include_directories(test_cache PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_definitions(test_cache PRIVATE UNICODE _UNICODE NOMINMAX)
target_link_libraries(test_cache PRIVATE Qt6::Test ws2_32)
add_test(NAME test_cache COMMAND test_cache)
set_tests_properties(test_cache PROPERTIES TIMEOUT 30)

# Upstream-validation DNSSEC semantics and per-upstream channel trust. The test
# supplies Upstream::ping, so no transport translation unit is linked.
add_executable(test_dnstrust test_dnstrust.cpp
    ${CMAKE_SOURCE_DIR}/src/core/DnsMessage.cpp
    ${CMAKE_SOURCE_DIR}/src/core/DnsSec.cpp
    ${CMAKE_SOURCE_DIR}/src/core/Pool.cpp
)
target_include_directories(test_dnstrust PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_definitions(test_dnstrust PRIVATE UNICODE _UNICODE NOMINMAX)
target_link_libraries(test_dnstrust PRIVATE Qt6::Test ws2_32)
add_test(NAME test_dnstrust COMMAND test_dnstrust)
set_tests_properties(test_dnstrust PROPERTIES TIMEOUT 30)

# ODoH configuration snapshots: refresh publication vs per-exchange capture (SEC-11).
add_executable(test_odoh test_odoh.cpp
    ${CMAKE_SOURCE_DIR}/src/core/DnsMessage.cpp
    ${CMAKE_SOURCE_DIR}/src/transports/OdohUpstream.cpp
    ${CMAKE_SOURCE_DIR}/src/transports/ProxyTunnel.cpp
    ${CMAKE_SOURCE_DIR}/src/core/ProxyProtocol.cpp
)
target_include_directories(test_odoh PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_definitions(test_odoh PRIVATE UNICODE _UNICODE NOMINMAX)
target_link_libraries(test_odoh PRIVATE Qt6::Test OpenSSL::SSL OpenSSL::Crypto winhttp ws2_32)
add_test(NAME test_odoh COMMAND test_odoh)
set_tests_properties(test_odoh PROPERTIES TIMEOUT 30)

# Rich-text escaping at the public-resolver browser tooltip/notice boundary (SEC-12).
add_executable(test_richtext test_richtext.cpp
    ${CMAKE_SOURCE_DIR}/src/core/Config.cpp
    ${CMAKE_SOURCE_DIR}/src/transports/Stamp.cpp
    ${CMAKE_SOURCE_DIR}/src/web/PublicResolversLoader.cpp
    ${CMAKE_SOURCE_DIR}/src/ui/Donate.cpp
    ${CMAKE_SOURCE_DIR}/src/ui/PublicResolverImport.cpp
    ${CMAKE_SOURCE_DIR}/src/ui/PublicResolversDialog.cpp
    ${CMAKE_SOURCE_DIR}/src/ui/ResolverJobs.cpp
)
target_include_directories(test_richtext PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_definitions(test_richtext PRIVATE UNICODE _UNICODE NOMINMAX)
target_link_libraries(test_richtext PRIVATE Qt6::Test Qt6::Widgets nlohmann_json::nlohmann_json winhttp)
add_test(NAME test_richtext COMMAND test_richtext)
set_tests_properties(test_richtext PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen" TIMEOUT 30)

# Trusted path / manifest / staging policy: pure helpers, no side effects.
add_executable(test_protectedpaths test_protectedpaths.cpp)
target_include_directories(test_protectedpaths PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_protectedpaths PRIVATE Qt6::Test)
add_test(NAME test_protectedpaths COMMAND test_protectedpaths)

# Installer destination policy, manifest planning and uninstall-script generation.
add_executable(test_installerpolicy test_installerpolicy.cpp)
target_include_directories(test_installerpolicy PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_installerpolicy PRIVATE Qt6::Test)
add_test(NAME test_installerpolicy COMMAND test_installerpolicy)

add_executable(test_setupoptions test_setupoptions.cpp)
target_include_directories(test_setupoptions PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_setupoptions PRIVATE Qt6::Test)
add_test(NAME test_setupoptions COMMAND test_setupoptions)

# Allow-ACE screening uses constants only: no filesystem or ACL API calls.
add_executable(test_setupsecurity test_setupsecurity.cpp)
target_include_directories(test_setupsecurity PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_definitions(test_setupsecurity PRIVATE UNICODE _UNICODE NOMINMAX)
target_link_libraries(test_setupsecurity PRIVATE Qt6::Test)
add_test(NAME test_setupsecurity COMMAND test_setupsecurity)

# Installer file placement and recovery use temporary roots only.
add_executable(test_setupfiles test_setupfiles.cpp
    ${CMAKE_SOURCE_DIR}/src/installer/setup.cpp
)
target_include_directories(test_setupfiles PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_definitions(test_setupfiles PRIVATE NS9_INSTALLER_TEST UNICODE _UNICODE NOMINMAX)
target_link_libraries(test_setupfiles PRIVATE Qt6::Test comctl32 shlwapi ole32 uuid shell32 advapi32 setupapi gdi32)
add_test(NAME test_setupfiles COMMAND test_setupfiles)
set_tests_properties(test_setupfiles PROPERTIES TIMEOUT 30)
