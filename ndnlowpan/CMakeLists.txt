add_static_library(ndnlowpan)

target_sources(ndnlowpan PRIVATE
               "${CMAKE_CURRENT_SOURCE_DIR}/src/ndnlowpan_util.c"
               "${CMAKE_CURRENT_SOURCE_DIR}/src/ndnlowpan_encode.c"
               "${CMAKE_CURRENT_SOURCE_DIR}/src/ndnlowpan_decode.c")
target_include_directories(ndnlowpan PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include/"
                                     PUBLIC "${ICNLOWPAN_INCLUDE_DIRS}")

if (BUILD_TESTING)
    add_executable(unittest-ndnlowpan "${CMAKE_CURRENT_SOURCE_DIR}/test/test.c")
    target_link_libraries(unittest-ndnlowpan unity ndnlowpan)
    add_test(ndnlowpan-tests unittest-ndnlowpan)
endif (BUILD_TESTING)
