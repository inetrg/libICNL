add_static_library(icnlowpan)

set(ICNLOWPAN_LIBS icnlowpan)
if (BUILD_NDNLOWPAN)
    LIST(APPEND ICNLOWPAN_LIBS "ndnlowpan")
endif (BUILD_NDNLOWPAN)

target_sources(icnlowpan PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src/icnlowpan.c")
target_link_libraries(${ICNLOWPAN_LIBS})
target_include_directories(icnlowpan PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include/")

set(ICNLOWPAN_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include/"
    CACHE INTERNAL "${ICNLOWPAN}: Include Directories" FORCE)

if (BUILD_TESTING)
    add_executable(unittest-icnlowpan "${CMAKE_CURRENT_SOURCE_DIR}/test/test.c")
    target_link_libraries(unittest-icnlowpan unity icnlowpan)
    add_test(icnlowpan-tests unittest-icnlowpan)
endif (BUILD_TESTING)
