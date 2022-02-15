
add_executable(spe_decode spe_decode.c)

target_include_directories(spe_decode PUBLIC
	"${PROJECT_SOURCE_DIR}/lib")
if(NOT (CMAKE_C_COMPILER_ID STREQUAL "MSVC"))
	target_compile_options(spe_decode PRIVATE -Werror -Wall -Wextra)
endif()
target_link_libraries(spe_decode PUBLIC spedecode)
