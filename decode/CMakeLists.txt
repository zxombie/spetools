
add_executable(spe_decode spe_decode.c)

target_include_directories(spe_decode PUBLIC
	"${PROJECT_SOURCE_DIR}/lib")
target_link_libraries(spe_decode PUBLIC spedecode)
