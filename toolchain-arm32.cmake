# toolchain-arm32.cmake
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

# Specify the cross-compiler
set(CMAKE_C_COMPILER arm-linux-gnueabihf-gcc)
set(CMAKE_CXX_COMPILER arm-linux-gnueabihf-g++)

# Set the sysroot to the ARM32 target environment
set(CMAKE_SYSROOT /usr/arm-linux-gnueabihf)

# Ensure CMake searches only in the sysroot for libraries, includes, and packages
set(CMAKE_FIND_ROOT_PATH /usr/arm-linux-gnueabihf)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Force compiler to use only target include paths, avoiding host /usr/include
set(CMAKE_C_FLAGS "-nostdinc -isystem /usr/lib/gcc-cross/arm-linux-gnueabihf/11/include -isystem /usr/arm-linux-gnueabihf/include/c++/11 -isystem /usr/arm-linux-gnueabihf/include/c++/11/arm-linux-gnueabihf -isystem /usr/arm-linux-gnueabihf/include" CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS "-nostdinc -isystem /usr/lib/gcc-cross/arm-linux-gnueabihf/11/include -isystem /usr/arm-linux-gnueabihf/include/c++/11 -isystem /usr/arm-linux-gnueabihf/include/c++/11/arm-linux-gnueabihf -isystem /usr/arm-linux-gnueabihf/include" CACHE STRING "" FORCE)
