cmake_minimum_required(VERSION 3.5.0) 

# 指定解决方案的名字 和版本
project(PEPack VERSION 0.1.0)


# 1.设置可执行文件的输出路径：
message(status ____________"${CMAKE_CURRENT_SOURCE_DIR}/build/")
SET(EXECUTABLE_OUTPUT_PATH "${CMAKE_CURRENT_SOURCE_DIR}/build/")
# 设置动态库输出路径
SET(LIBRARY_OUTPUT_PATH ${EXECUTABLE_OUTPUT_PATH}) 

add_subdirectory(src/pePack)
add_subdirectory(src/stub)