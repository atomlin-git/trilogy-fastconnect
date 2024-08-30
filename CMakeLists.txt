cmake_minimum_required(VERSION 2.8...3.15)
project(tfc LANGUAGES C CXX)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CMAKE_CXX_STANDARD 20)

include_directories(includes)
add_library(${PROJECT_NAME} SHARED)
target_sources(${PROJECT_NAME} PRIVATE source/main.cpp)
target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_20)
set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME ${PROJECT_NAME} SUFFIX ".asi")