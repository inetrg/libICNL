cmake_minimum_required(VERSION 3.1)

project(icnlowpan VERSION 0.1 LANGUAGES C)

option(BUILD_DOC        "Build documentation"   ON)
option(BUILD_DEBUG      "Build with debug"      ON)
option(BUILD_NDNLOWPAN  "Build NDNLoWPAN"       ON)
option(BUILD_CCNLOWPAN  "Build CCNLoWPAN"       OFF)

include(CTest)
if (BUILD_TESTING)
    add_library(unity STATIC "Unity/src/unity.c")
    target_include_directories(unity PUBLIC "Unity/src")
endif (BUILD_TESTING)

if (BUILD_DOC)
    find_package(Doxygen)
    if (DOXYGEN_FOUND)
        set(DOXYGEN_IN ${CMAKE_CURRENT_SOURCE_DIR}/doc/Doxyfile.in)
        set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
        configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)
        message("Doxygen build started")
        add_custom_target( doc_doxygen ALL
            COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            COMMENT "Generating API documentation with Doxygen"
            VERBATIM )
    else (DOXYGEN_FOUND)
        message("Doxygen not found")
    endif (DOXYGEN_FOUND)
endif (BUILD_DOC)

FUNCTION(add_static_library TARGET)
    add_library(${TARGET} STATIC "")
	set_target_properties(${TARGET} PROPERTIES
		ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
		LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
		RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
	)
ENDFUNCTION()

if (BUILD_DEBUG)
    add_definitions(-DICNL_DEBUG=1)
endif (BUILD_DEBUG)

add_definitions(-DMODULE_ICNLOWPAN)

if (BUILD_NDNLOWPAN)
    add_definitions(-DMODULE_NDNLOWPAN)
endif(BUILD_NDNLOWPAN)

add_subdirectory(icnlowpan)

if (BUILD_NDNLOWPAN)
    add_subdirectory(ndnlowpan)
endif (BUILD_NDNLOWPAN)
