
cmake_minimum_required( VERSION 3.1 )
project( xrootd-multiuser )

set( CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake )

find_package( Xrootd REQUIRED )

set( CMAKE_CXX_STANDARD 11 )
if( CMAKE_COMPILER_IS_GNUCXX )
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror" )
endif()
SET( CMAKE_SHARED_LINKER_FLAGS "-Wl,--no-undefined")
SET( CMAKE_MODULE_LINKER_FLAGS "-Wl,--no-undefined")

# For getpwnam_r
add_definitions(-D_POSIX_C_SOURCE=200809L)

include_directories(${XROOTD_INCLUDES})

add_library(XrdMultiuser SHARED src/multiuser.cpp)
target_link_libraries(XrdMultiuser ${XROOTD_UTILS_LIB})
set_target_properties(XrdMultiuser PROPERTIES SUFFIX ".so" LINK_FLAGS "-Wl,--version-script=${CMAKE_SOURCE_DIR}/configs/export-lib-symbols")

SET(LIB_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/lib" CACHE PATH "Install path for libraries")

install(
  TARGETS XrdMultiuser
  LIBRARY DESTINATION ${LIB_INSTALL_DIR})

