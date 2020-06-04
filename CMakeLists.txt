
cmake_minimum_required( VERSION 2.8 )
project( xrootd-multiuser )

set( CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake )

find_package( Xrootd REQUIRED )
find_package( Cap REQUIRED )

if(NOT XROOTD_PLUGIN_VERSION)
  find_program(XROOTD_CONFIG_EXECUTABLE xrootd-config)
  exec_program(${XROOTD_CONFIG_EXECUTABLE} ARGS "--plugin-version" OUTPUT_VARIABLE XROOTD_PLUGIN_VERSION RETURN_VALUE RETVAR)
  set(XROOTD_PLUGIN_VERSION ${XROOTD_PLUGIN_VERSION} CACHE INTERNAL "")
endif()

macro(use_cxx11)
  if (CMAKE_VERSION VERSION_LESS "3.1")
    if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
      set (CMAKE_CXX_FLAGS "-std=gnu++11 ${CMAKE_CXX_FLAGS}")
    endif ()
  else ()
    set (CMAKE_CXX_STANDARD 11)
  endif ()
endmacro(use_cxx11)
use_cxx11()

if( CMAKE_COMPILER_IS_GNUCXX )
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror" )
endif()
SET( CMAKE_SHARED_LINKER_FLAGS "-Wl,--no-undefined")
SET( CMAKE_MODULE_LINKER_FLAGS "-Wl,--no-undefined")

# For getpwnam_r
add_definitions(-D_POSIX_C_SOURCE=200809L)

include_directories(${XROOTD_INCLUDES})

add_library(XrdMultiuser SHARED src/multiuser.cpp)
target_link_libraries(XrdMultiuser -ldl ${CAP_LIB} ${XROOTD_UTILS_LIB} ${XROOTD_SERVER_LIB})
set_target_properties(XrdMultiuser PROPERTIES OUTPUT_NAME "XrdMultiuser-${XROOTD_PLUGIN_VERSION}" SUFFIX ".so" LINK_FLAGS "-Wl,--version-script=${CMAKE_SOURCE_DIR}/configs/export-lib-symbols")

SET(LIB_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/lib" CACHE PATH "Install path for libraries")

install(
  TARGETS XrdMultiuser
  LIBRARY DESTINATION ${LIB_INSTALL_DIR}
)

install(
  FILES ${CMAKE_SOURCE_DIR}/configs/xrootd-privileged@.service
  DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/systemd/system
)
