# Run after the primary project initializes the Darwin toolchain flags.
if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
  string(APPEND CMAKE_CXX_FLAGS " -DSUGARCHAIN_FILE_BACKED_POOL_DIAGNOSTIC")
endif()
