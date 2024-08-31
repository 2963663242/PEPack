# 从文件夹从获取文件的决定路径
file(GLOB SOURCE_FILES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/*.h")
add_executable(pePack ${SOURCE_FILES})

add_dependencies(pePack stub)


# 添加包含目录
target_include_directories(pePack PUBLIC
	${CMAKE_SOURCE_DIR}/src/stub
)