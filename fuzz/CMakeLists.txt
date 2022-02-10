
function(spefuzz SAN)
	add_executable(spe_fuzz_${SAN} spe_fuzz.cc)

	target_include_directories(spe_fuzz_${SAN} PUBLIC
		"${PROJECT_SOURCE_DIR}/lib")
	target_link_libraries(spe_fuzz_${SAN} PUBLIC
		spedecode_fuzz_${SAN})

	target_compile_options(spe_fuzz_${SAN} PRIVATE
		-g -O1 -fsanitize=fuzzer)
	target_link_libraries(spe_fuzz_${SAN} PRIVATE
		-fsanitize=fuzzer,${SAN})
endfunction()

spefuzz(address)
spefuzz(undefined)
