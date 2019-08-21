cmake_minimum_required(VERSION 2.8)
project(rc5 C ASM)

add_library(bufferio Implementierung/bufferio.h Implementierung/bufferio.c)
add_executable(rc5 Implementierung/rc5.c Implementierung/rc5.S Implementierung/test.h Implementierung/test.c Implementierung/references/rfc2040.h Implementierung/references/rfc2040.c)
add_executable(enlighten Implementierung/enlighten.c)
add_executable(key_expansion Implementierung/key_expansion.c Implementierung/key_expansion.S Implementierung/rc5.h)
target_link_libraries(rc5 bufferio -lbsd)
target_link_libraries(enlighten bufferio)

set(CMAKE_C_FLAGS "-g -O2 -Wall -Wextra -pedantic -Wunused -Wrestrict")