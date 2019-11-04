#.rst:
# FindRapidJSON
# -----------
# Finds the RapidJSON library
#
# This will define the following variables::
#
# RAPIDJSON_FOUND - system has RapidJSON parser
# RAPIDJSON_INCLUDE_DIRS - the RapidJSON parser include directory
#

find_package(PkgConfig)
if(PKG_CONFIG_FOUND)
  pkg_check_modules(PC_RapidJSON RapidJSON>=${RapidJSON_FIND_VERSION} QUIET)
endif()

if(PC_RapidJSON_VERSION)
  set(RapidJSON_VERSION ${PC_RapidJSON_VERSION})
else()
  find_package(RapidJSON ${RapidJSON_FIND_VERSION} CONFIG REQUIRED QUIET)
endif()

find_path(RapidJSON_INCLUDE_DIR NAMES rapidjson/rapidjson.h
                                PATHS ${PC_RapidJSON_INCLUDEDIR})


include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(RapidJSON
                                  REQUIRED_VARS RapidJSON_INCLUDE_DIR RapidJSON_VERSION
                                  VERSION_VAR RapidJSON_VERSION)

if(RAPIDJSON_FOUND)
  set(RAPIDJSON_INCLUDE_DIRS ${RapidJSON_INCLUDE_DIR})
endif()

mark_as_advanced(RapidJSON_INCLUDE_DIR)

