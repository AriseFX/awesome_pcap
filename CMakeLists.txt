cmake_minimum_required(VERSION 3.10)
project(pcap_demo C)
# CMAKE_BINARY_DIR === ./build/pcap_demo/
# WROKDIR ./deps
set(WROKDIR ${CMAKE_BINARY_DIR}/../..)
#  COLOR DEFINE
if(NOT WIN32)
string(ASCII 27 Esc)
set(ColourReset "${Esc}[m")
set(ColourBold  "${Esc}[1m")
set(Red         "${Esc}[31m")
set(Green       "${Esc}[32m")
set(Yellow      "${Esc}[33m")
set(Blue        "${Esc}[34m")
set(Magenta     "${Esc}[35m")
set(Cyan        "${Esc}[36m")
set(White       "${Esc}[37m")
set(BoldRed     "${Esc}[1;31m")
set(BoldGreen   "${Esc}[1;32m")
set(BoldYellow  "${Esc}[1;33m")
set(BoldBlue    "${Esc}[1;34m")
set(BoldMagenta "${Esc}[1;35m")
set(BoldCyan    "${Esc}[1;36m")
set(BoldWhite   "${Esc}[1;37m")
endif() # COLOR DEFINE END
set(mode $ENV{MODE})
set(build $ENV{onlyDeps})
message(
  STATUS 
  "${BoldGreen}mode: " 
  ${mode} 
  "${ColourReset}"
)
message(
  STATUS 
  "${BoldGreen}build: " 
  ${build} 
  "${ColourReset}"
)
# deps

include(cmake/cJSON.cmake) # cJSON
include(cmake/rax.cmake)   # rax

if (build STREQUAL "true") 
  return()
endif()

if ( mode STREQUAL "debug") 
  SET(CMAKE_BUILD_TYPE "Debug")  
  message(
    STATUS
    "${BoldBlue}"
    "enable debug mode"
    "${ColourReset}"
  )
  add_compile_options(-rdynamic)
  message(STATUS 
  "${BoldBlue}"
  "optional:-rdynamic"
  "${ColourReset}"
  ) 
endif()

set(CMAKE_C_STANDARD 99) # C99

aux_source_directory (. DIR_SRCS) # 搜索目录下所有源文件

add_executable(pcap_demo 
${DIR_SRCS}
)

add_dependencies(pcap_demo cJSON)
message(
  STATUS
  "${BoldRed}"
  ${cJSONDownload}
  "${ColourReset}"
)
target_link_libraries(pcap_demo ${CJSON_LIB})
target_include_directories(pcap_demo PRIVATE ${CJSON_DIR})

if ((CMAKE_COMPILER_IS_GNUCC ) AND ( mode STREQUAL "release"))
  message(
    STATUS 
    "${BoldBlue}"
    "enable O1 optimization" 
    "${ColourReset}"
  )
  add_compile_options(-O1)
endif() # CMAKE_COMPILER_IS_GNUCXX
find_library(
  PCAP_LIBRARY
  NAMES pcap
)

if ("${PCAP_LIBRARY}" STREQUAL "") 
  message(
    FATAL_ERROR 
    "${BoldRed}could not find libpcap${ColourReset}"
  )
endif()

message(
  STATUS 
  "${BoldGreen}find libpcap in " 
  ${PCAP_LIBRARY} 
  "${ColourReset}"
)
target_link_libraries(
  ${PROJECT_NAME}
  ${PCAP_LIBRARY} 
  -lpthread
  -lm
)