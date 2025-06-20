cmake_minimum_required(VERSION 3.15)

project(LBR VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
add_compile_options("-w")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -g")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -g")
set(LOG_LEVEL "LOG_NONE" CACHE STRING "set the log level")
add_definitions( -DLOG_LEVEL=${LOG_LEVEL})
# add_definitions( -D LOG_LEVEL=LOG_NONE)
# add_definitions( -D MY_DEBUG)
# add_definitions( -D NO_STATIC)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

file(GLOB SOURCES "src/engine/*.cpp" "src/utils/*.cpp")
add_library(profiler SHARED ${SOURCES})


target_include_directories(profiler PUBLIC ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/include/log ${PROJECT_SOURCE_DIR}/third_party/DynamoRIO/include) 

add_subdirectory(third_party)
link_directories(${PROJECT_SOURCE_DIR}/third_party/DynamoRIO/lib64/debug)
target_link_libraries(profiler PRIVATE pthread ${PROJECT_SOURCE_DIR}/third_party/DynamoRIO/lib64/release/libdynamorio_static.a unwind unwind-generic)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
    add_definitions(-D__x86_64__)
    message("the arch is x86_64")
    target_compile_definitions(profiler PRIVATE LINUX X86_64)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm")
    add_definitions(-D__arm__)
    message("the arch is arm")
    target_compile_definitions(profiler PRIVATE LINUX ARM_32)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
    add_definitions(-D__aarch64__)
    target_compile_definitions(profiler PRIVATE LINUX ARM_64)
    message("the arch is aarch64")
else()
    message(FATAL_ERROR "Unsupported architecture")
endif()
