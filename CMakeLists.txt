cmake_minimum_required(VERSION 3.0)
project(main)

set(CMAKE_CXX_STANDARD 20)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBUDEV REQUIRED libudev)
pkg_check_modules(LIBMAGIC REQUIRED libmagic)
add_executable(main main.cpp)

# Включаем include-директории пакета
target_include_directories(main PRIVATE
        ${LIBUDEV_INCLUDE_DIRS}
        ${LIBMAGIC_INCLUDE_DIRS}
)

# Прокидываем дополнительные флаги компилятора (если pkg-config их выдаёт)
target_compile_options(main PRIVATE
        ${LIBUDEV_CFLAGS_OTHER}
        ${LIBMAGIC_CFLAGS_OTHER}
)


# Линкуем библиотеки
target_link_libraries(main PRIVATE
        ${LIBUDEV_LDFLAGS} ${LIBUDEV_LIBRARIES}
        ${LIBMAGIC_LDFLAGS} ${LIBMAGIC_LIBRARIES}
)