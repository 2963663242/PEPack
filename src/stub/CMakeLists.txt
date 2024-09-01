if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(STATUS "Compiling for 64-bit system")
    set(ASM_FILE start.asm)
    set(IS_64BIT TRUE)
else()
    message(STATUS "Compiling for 32-bit system")
    # 32位系统的设置
    set(IS_32BIT TRUE)
    set(ASM_FILE start32.asm)
endif()


add_library(stub SHARED 
	dllmain.cpp
	stub.cpp
	stub.h
	${ASM_FILE}
	)

# ÆôÓÃ»ã±àÓïÑÔÖ§³Ö
enable_language(ASM_MASM)


# 对特定目标禁用 SAFESEH
target_link_options(stub PRIVATE /SAFESEH:NO)