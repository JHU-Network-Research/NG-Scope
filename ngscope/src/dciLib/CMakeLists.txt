file(GLOB_RECURSE SOURCES "*.cpp" "*.c")
list(REMOVE_ITEM SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/ngscope_rx.c)
list(REMOVE_ITEM SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/record_ring_buffer.c)
list(REMOVE_ITEM SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/rach_filter.c)
list(REMOVE_ITEM SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/decode_rar.cpp)
list(REMOVE_ITEM SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/mac_pcap.c)
list(REMOVE_ITEM SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/pcapng.c)
list(REMOVE_ITEM SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/security_ctx.c)
list(REMOVE_ITEM SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/security_rrc.cpp)
# Called from srsran_phy (ngscope_dci.c), so it cannot live in ngscope_dci, which links
# against srsran_phy. Same arrangement as rach_filter above.
list(REMOVE_ITEM SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/tbs_table_probe.c)

#file(GLOB_RECURSE SOURCES "*.c")

# Vendored TOML parser (MIT) backing the .toml config backend -- see
# ngscope/external/tomlc99/README.md
set(TOMLC99_DIR ${CMAKE_SOURCE_DIR}/ngscope/external/tomlc99)

add_library(ngscope_dci STATIC ${SOURCES} ${TOMLC99_DIR}/toml.c)
target_include_directories(ngscope_dci PUBLIC ${TOMLC99_DIR})

target_link_libraries(ngscope_dci config rrc_asn1 asn1_utils srsran_common srsran_mac)

# Link with C++ standard library
if(BUILD_STATIC)
  target_link_libraries(ngscope_dci stdc++)
endif()

if (LIBASN4G)
  target_link_libraries(ngscope_dci ${LIBASN4G_LIBRARY})
endif(LIBASN4G)

if (LIBASN5G)
  target_link_libraries(ngscope_dci ${LIBASN5G_LIBRARY})
endif(LIBASN5G)

if(ENABLE_GUI AND SRSGUI_FOUND)
  target_link_libraries(ngscope_dci ${SRSGUI_LIBRARIES})
endif()

add_library(ngscope_rx STATIC ngscope_rx.c record_ring_buffer.c)
target_include_directories(ngscope_rx PUBLIC
    ${CMAKE_SOURCE_DIR}/ngscope/hdr
    ${CMAKE_SOURCE_DIR}/lib/include
)

add_library(rach_filter STATIC rach_filter.c decode_rar.cpp)
target_include_directories(rach_filter PUBLIC
  ${CMAKE_SOURCE_DIR}/ngscope/hdr
  ${CMAKE_SOURCE_DIR}/lib/include
)

add_library(rrc_security STATIC security_ctx.c security_rrc.cpp)
target_include_directories(rrc_security PUBLIC
  ${CMAKE_SOURCE_DIR}/ngscope/hdr
  ${CMAKE_SOURCE_DIR}/lib/include
)

add_library(mac_pcap STATIC mac_pcap.c pcapng.c)
target_include_directories(mac_pcap PUBLIC
    ${CMAKE_SOURCE_DIR}/ngscope/hdr
    ${CMAKE_SOURCE_DIR}/lib/include
)
target_link_libraries(mac_pcap srsran_common)

add_library(tbs_table_probe STATIC tbs_table_probe.c)
target_include_directories(tbs_table_probe PUBLIC
  ${CMAKE_SOURCE_DIR}/ngscope/hdr
  ${CMAKE_SOURCE_DIR}/lib/include
)
target_link_libraries(ngscope_rx srsran_phy)
target_link_libraries(rach_filter rrc_security mac_pcap srsran_common srsran_mac)
