# LIBUV_FOUND - true if library and headers were found
# LIBUV_INCLUDE_DIRS - include directories
# LIBUV_LIBRARIES - library directories

find_package(PkgConfig)
pkg_check_modules(PC_LIBUV QUIET libuv)

find_path(LIBUV_INCLUDE_DIR uv.h
	HINTS ${PC_LIBUV_INCLUDEDIR} ${PC_LIBUV_INCLUDE_DIRS} PATH_SUFFIXES libuv)

find_library(LIBUV_LIBRARY NAMES uv libuv
	HINTS ${PC_LIBUV_LIBDIR} ${PC_LIBUV_LIBRARY_DIRS})

set(LIBUV_LIBRARIES ${LIBUV_LIBRARY})
set(LIBUV_INCLUDE_DIRS ${LIBUV_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(LIBUV DEFAULT_MSG LIBUV_LIBRARY LIBUV_INCLUDE_DIR)

mark_as_advanced(LIBUV_INCLUDE_DIR LIBUV_LIBRARY)
