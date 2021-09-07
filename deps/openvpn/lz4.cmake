set(lz4_srcs
  lz4.c
  )

PREPEND(lz4_src_with_path "deps/openvpn/lz4/lib/" ${lz4_srcs})
add_library(lz4 SHARED ${lz4_src_with_path})
set_target_properties(lz4 PROPERTIES LINKER_LANGUAGE C)
target_include_directories(lz4 PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/lz4/lib")
