cmake_minimum_required(VERSION 3.10)

if(DEFINED SPE_CLANG_TIDY)
	set(CMAKE_C_CLANG_TIDY
	  ${SPE_CLANG_TIDY};
	  -header-filter=.;
	  -checks=cert-*,clang-analyzer-*,misc-*,portability-*;
	  -warnings-as-errors=*;
	)
endif()

project(SPEDecode)

if(NOT DEFINED SPE_FUZZ)
	set(SPE_FUZZ "no")
endif()

add_subdirectory(lib)
add_subdirectory(decode)
if (SPE_FUZZ STREQUAL "yes")
	add_subdirectory(fuzz)
endif()
