#macro(replace_if_different SOURCE DST)
#	set(extra_macro_args ${ARGN})
#	set(options CREATE)
#	set(one_value_args)
#	set(multi_value_args)
#	cmake_parse_arguments(REPLACE_IF_DIFFERENT "${options}" "${one_value_args}" "${multi_value_args}" "${extra_macro_args}")
#
#	if (REPLACE_IF_DIFFERENT_CREATE AND (NOT (EXISTS "${DST}")))
#		file(WRITE "${DST}" "")
#	endif()
#
#	execute_process(COMMAND ${CMAKE_COMMAND} -E compare_files "${SOURCE}" "${DST}" RESULT_VARIABLE DIFFERENT OUTPUT_QUIET ERROR_QUIET)
#
#	if (DIFFERENT)
#		execute_process(COMMAND ${CMAKE_COMMAND} -E rename "${SOURCE}" "${DST}")
#	else()
#		execute_process(COMMAND ${CMAKE_COMMAND} -E remove "${SOURCE}")
#	endif()
#endmacro()

include(WiresharkPlugin)

set_module_info(devp2p 0 0 0 0)

#set(TMPFILE "./BuildInfo.h.tmp")
#set(OUTFILE "./BuildInfo.h")
#set(README "./README.md")

#configure_file("${README}" "${TMPFILE}")
#replace_if_different("${TMPFILE}" "${OUTFILE}" CREATE)

set(DISSECTOR_SRC
	packet-ethereum.c
)

set(PLUGIN_FILES
	plugin.c
	${DISSECTOR_SRC}
)

set_source_files_properties(
	${PLUGIN_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

register_plugin_files(plugin.c
	plugin
	${DISSECTOR_SRC}
)

add_plugin_library(devp2p epan)

target_link_libraries(devp2p epan)

install_plugin(devp2p epan)

file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")
CHECKAPI(
	NAME
	  devp2p
	SWITCHES
	  -g abort -g termoutput -build
	SOURCES
	  ${DISSECTOR_SRC}
	  ${DISSECTOR_HEADERS}
)
