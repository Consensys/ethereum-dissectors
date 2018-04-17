
include(WiresharkPlugin)

set_module_info(devp2p 0 0 0 0)

set(DISSECTOR_SRC
	packet-ethereum.c
)

set(PLUGIN_FILES
	plugin.c
	common.cpp
	commonData.cpp
	FixedHash.cpp
	RLP.cpp
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
