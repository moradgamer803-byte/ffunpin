cmake_minimum_required(VERSION 3.22.1)
project(ffunpin C)

add_library(ffunpin SHARED ffunpin.c)

find_library(log-lib log)
target_link_libraries(ffunpin ${log-lib})
