add_static_library(core)

set(CORE_LIBS core)
if (BUILD_NDNLOWPAN)
    LIST(APPEND CORE_LIBS "ndnlowpan")
endif (BUILD_NDNLOWPAN)

target_sources(core PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src/core.c")
target_link_libraries(${CORE_LIBS})
target_include_directories(core PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include/")

if (BUILD_TESTING)
    add_executable(unittest-core "${CMAKE_CURRENT_SOURCE_DIR}/test/test.c")
    target_link_libraries(unittest-core unity core)
    add_test(core-tests unittest-core)
endif (BUILD_TESTING)
