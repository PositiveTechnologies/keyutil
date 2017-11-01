cmake_minimum_required(VERSION 2.8)

project(keyutil)

find_package(PkgConfig REQUIRED)

pkg_check_modules(OPENSSL REQUIRED libssl libcrypto)

include_directories(${OPENSSL_INCLUDE_DIR})

add_executable(${PROJECT_NAME} "main.c")

target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARIES})
