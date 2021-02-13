cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)

# Project
get_filename_component(PROJECT_DIR "${CMAKE_CURRENT_SOURCE_DIR}" ABSOLUTE)

#### find: Boost Lib
set(Boost_USE_STATIC_LIBS OFF) 
set(Boost_USE_MULTITHREADED ON)  
set(Boost_USE_STATIC_RUNTIME OFF) 
find_package(Boost 1.73.0 COMPONENTS)

if(Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS}) 
endif()

###########################

set(PROJECT_NAME dooked)
set(CMAKE_BUILD_TYPE Release)
include_directories(${PROJECT_DIR}/include)
include_directories(${PROJECT_DIR}/CLI11/include)
include_directories(${PROJECT_DIR}/json/single_include)
include_directories(${PROJECT_DIR}/spdlog/include)


link_directories(/usr/lib)
link_libraries(pthread ssl crypto)

# Outputs
set(OUTPUT_DEBUG ${PROJECT_DIR}/bin)
set(OUTPUT_RELEASE ${PROJECT_DIR}/bin)

project(${PROJECT_NAME} CXX)

# Define Release by default.
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Release")
  message(STATUS "Build type not specified: Use Release by default.")
endif(NOT CMAKE_BUILD_TYPE)

############## Artefacts Output ############################
# Defines outputs , depending BUILD TYPE                   #
############################################################

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PROJECT_DIR}/${OUTPUT_DEBUG}")
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_DIR}/${OUTPUT_DEBUG}")
  set(CMAKE_EXECUTABLE_OUTPUT_DIRECTORY "${PROJECT_DIR}/${OUTPUT_DEBUG}")
else()
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PROJECT_DIR}/${OUTPUT_RELEASE}")
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_DIR}/${OUTPUT_RELEASE}")
  set(CMAKE_EXECUTABLE_OUTPUT_DIRECTORY "${PROJECT_DIR}/${OUTPUT_RELEASE}")
endif()

# Messages
message("${PROJECT_NAME}: MAIN PROJECT: ${CMAKE_PROJECT_NAME}")
message("${PROJECT_NAME}: CURR PROJECT: ${CMAKE_CURRENT_SOURCE_DIR}")
message("${PROJECT_NAME}: CURR BIN DIR: ${CMAKE_CURRENT_BINARY_DIR}")

############### Files & Targets ############################
# Files of project and target to build                     #
############################################################

# Source Files
set(SRC_FILES
    ./source/dns/dns.cpp
    ./source/dns/dns_resolver.cpp
    ./source/http/resolver.cpp
    ./source/http/requests_handler.cpp
    ./source/utils/constants.cpp
    ./source/utils/io_utils.cpp
    ./source/utils/string_utils.cpp
    ./source/utils/random_utils.cpp
    ./source/utils/ucstring.cpp
    ./source/cli_preprocessor.cpp
    ./source/main.cpp
)

source_group("Sources" FILES ${SRC_FILES})

# Header Files
set(HEADERS_FILES
    ./include/dns/dns.hpp
    ./include/dns/dns_resolver.hpp
    ./include/http/resolver.hpp
    ./include/http/requests_handler.hpp
    ./include/utils/constants.hpp
    ./include/utils/containers.hpp
    ./include/utils/dns_utils.hpp
    ./include/utils/exceptions.hpp
    ./include/utils/io_utils.hpp
    ./include/utils/probe_result.hpp
    ./include/utils/random_utils.hpp
    ./include/utils/string_utils.hpp
    ./include/utils/ucstring.hpp
    ./include/cli_preprocessor.hpp
)

source_group("Headers" FILES ${HEADERS_FILES})

# Add executable to build.
add_executable(${PROJECT_NAME} 
   ${SRC_FILES} ${HEADERS_FILES}
)

if(NOT MSVC)
   set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -O3")
   if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
       set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
   endif()
endif(NOT MSVC)

# Preprocessor definitions
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(${PROJECT_NAME} PRIVATE 
   -D_DEBUG 
   -D_CONSOLE 
    )
    if(MSVC)
        target_compile_options(${PROJECT_NAME} PRIVATE  /W3 /MD /Od /Zi /EHsc /std:c++17)
    endif()
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_definitions(${PROJECT_NAME} PRIVATE 
   -DNDEBUG 
   -D_CONSOLE 
    )
    if(MSVC)
        target_compile_options(${PROJECT_NAME} PRIVATE  /W3 /GL /Oi /Gy /Zi /EHsc /std:c++17)
    endif()
endif()
