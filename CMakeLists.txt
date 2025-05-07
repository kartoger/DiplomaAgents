cmake_minimum_required(VERSION 3.0)
project(DiplomaAgents)

set(CMAKE_CXX_STANDARD 20)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBUDEV REQUIRED libudev)
pkg_check_modules(LIBMAGIC REQUIRED libmagic)


add_library(functions_for_all STATIC
        Functions_for_all/For_all.cpp
)
target_include_directories(functions_for_all PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/Functions_for_all
)

add_executable(main main.cpp
        For_SSH_GDM/For_SSH_GDM.cpp
        Functions_for_all/For_all.cpp
        For_USB/For_USB.cpp
        For_ScanUsers/For_ScanUsers.cpp
        For_FileSystem/FileMonitoring.cpp
)

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
        functions_for_all
)

# Новый таргет для Only-USB
add_executable(FileSystem
        Only_FileSystem/Final_fileAccess.cpp
)
add_executable(OnlyUSB
        Only_USB/Only-USB.cpp
)
add_executable(ScanUsers
        Only_ScanUsers/Only_ScanUsers.cpp
)
target_compile_options(FileSystem PRIVATE
        ${LIBUDEV_CFLAGS_OTHER}
        ${LIBMAGIC_CFLAGS_OTHER}
)
target_compile_options(ScanUsers PRIVATE
${LIBUDEV_CFLAGS_OTHER}
${LIBMAGIC_CFLAGS_OTHER}
)
# Прокидываем дополнительные флаги компилятора (если pkg-config их выдаёт)
target_compile_options(OnlyUSB PRIVATE
        ${LIBUDEV_CFLAGS_OTHER}
        ${LIBMAGIC_CFLAGS_OTHER}
)


# Линкуем библиотеки
target_link_libraries(OnlyUSB PRIVATE
        ${LIBUDEV_LDFLAGS} ${LIBUDEV_LIBRARIES}
        ${LIBMAGIC_LDFLAGS} ${LIBMAGIC_LIBRARIES}
)

add_executable(ssh_gdm2
        Only_SSH_GDM/ssh_gdm2.cpp
)


# Прокидываем дополнительные флаги компилятора (если pkg-config их выдаёт)
target_compile_options(ssh_gdm2 PRIVATE
        ${LIBUDEV_CFLAGS_OTHER}
        ${LIBMAGIC_CFLAGS_OTHER}
)


# Линкуем библиотеки
target_link_libraries(ssh_gdm2 PRIVATE
        ${LIBUDEV_LDFLAGS} ${LIBUDEV_LIBRARIES}
        ${LIBMAGIC_LDFLAGS} ${LIBMAGIC_LIBRARIES}
)