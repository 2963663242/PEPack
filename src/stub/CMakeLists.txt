file(GLOB SOURCE_FILES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/*.h"  "${CMAKE_CURRENT_SOURCE_DIR}/*.asm")
add_library(stub SHARED ${SOURCE_FILES})

# ∆Ù”√ª„±‡”Ô—‘÷ß≥÷
enable_language(ASM_MASM)