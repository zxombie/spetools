cmake_minimum_required(VERSION 3.10)

project(SPEDecode)

if(NOT DEFINED SPE_FUZZ)
	set(SPE_FUZZ "no")
endif()

add_subdirectory(lib)
add_subdirectory(decode)
if (SPE_FUZZ STREQUAL "yes")
	add_subdirectory(fuzz)
endif()
