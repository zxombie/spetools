
set(SPEDECODE_FILES
	context.c
	packet.c
	packet_decode.c
)
add_library(spedecode
	${SPEDECODE_FILES}
)
if(NOT (CMAKE_C_COMPILER_ID STREQUAL "MSVC"))
	target_compile_options(spedecode PRIVATE -Werror -Wall -Wextra)
endif()

if (SPE_FUZZ STREQUAL "yes")
	function(spedecodefuzz SAN)
		add_library(spedecode_fuzz_${SAN}
			${SPEDECODE_FILES}
		)
		target_compile_options(spedecode_fuzz_${SAN}
			PRIVATE
			-g -O1 -fsanitize=fuzzer,${SAN} -DSPE_FUZZ_TARGET)
	endfunction()

	spedecodefuzz(address)
	spedecodefuzz(undefined)
endif()
