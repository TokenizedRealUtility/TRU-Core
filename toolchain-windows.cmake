# toolchain-windows.cmake
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR i686)

# Specify the cross compiler
set(CMAKE_C_COMPILER /opt/mxe/usr/bin/i686-w64-mingw32.static-gcc)
set(CMAKE_CXX_COMPILER /opt/mxe/usr/bin/i686-w64-mingw32.static-g++)
set(CMAKE_RC_COMPILER /opt/mxe/usr/bin/i686-w64-mingw32.static-windres)

# Where to look for libraries and headers
set(CMAKE_FIND_ROOT_PATH /opt/mxe/usr/i686-w64-mingw32.static)

# Adjust the default behavior of find commands
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

# Set static linking
set(BUILD_SHARED_LIBS OFF)
set(CMAKE_EXE_LINKER_FLAGS "-static")
