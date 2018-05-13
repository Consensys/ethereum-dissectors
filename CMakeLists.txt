cmake_minimum_required(VERSION 3.1.0)
project(wireshark-ethdevp2pdisco C)

######################################
# CMAKE Environment setup and checks #
######################################
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

include(MacroEnsureOutOfSourceBuild)
macro_ensure_out_of_source_build("${PROJECT_NAME} requires an out of source build. Please create a separate build directory and run 'cmake /path/to/${PROJECT_NAME} [options]' there.")

##############################
# Find and load dependencies #
##############################
find_package(Wireshark REQUIRED)
include_directories (${Wireshark_INCLUDE_DIR})
INCLUDE(UseMakeDissectorReg)

find_package(GLIB2 REQUIRED)
include_directories (${GLIB2_INCLUDE_DIRS})

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

########################
# Specify Source filed #
########################
set(DISSECTOR_SRC
  packet-ethereum.c
)

#Generated plugin.c file contains plugin entry point.
set(PLUGIN_FILES
  plugin.c
  ${DISSECTOR_SRC}
)

##################
# Compile Plugin #
##################
#Scan DISSECTOR_FILES for functions matching
#'proto_register_' and 'proto_reg_handoff'
#then generate entry points in plugin.c.
register_dissector_files(plugin.c
  plugin
  ${DISSECTOR_SRC}
)

#Create the library file from all source
#files, including the generated plugin.c.
#MODULE is required for Mac, as SHARED
#produces a .dylib file instead of .so.
add_library(wireshark-ethdevp2pdisco MODULE
  ${PLUGIN_FILES}
  )

#Prevent generated file from being names libX.so.
set_target_properties(wireshark-ethdevp2pdisco
  PROPERTIES PREFIX "")

#Link against wireshark library.
target_link_libraries(wireshark-ethdevp2pdisco wireshark glib-2.0)

###########################################
# Set Plugin install location and INSTALL #
###########################################
IF ( NOT CMAKE_INSTALL_LIBDIR )
  set(CMAKE_INSTALL_LIBDIR ~/.config/wireshark/plugins)
ENDIF ( NOT CMAKE_INSTALL_LIBDIR )
MESSAGE (STATUS "Plugin will be installed in: ${CMAKE_INSTALL_LIBDIR}")

install(TARGETS wireshark-ethdevp2pdisco
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/ NAMELINK_SKIP
)
