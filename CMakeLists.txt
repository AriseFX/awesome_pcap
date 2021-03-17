cmake_minimum_required(VERSION 3.10)
project(pcap_demo C)

set(CMAKE_C_STANDARD 99)

add_executable(pcap_demo main.c protocol.c protocol_info.c ssh.c callback.c)
if (CMAKE_COMPILER_IS_GNUCXX)
  add_compile_options(-O1)
endif(CMAKE_COMPILER_IS_GNUCXX)

target_link_libraries(${PROJECT_NAME} /usr/local/lib/libpcap.so -lpthread -lm)