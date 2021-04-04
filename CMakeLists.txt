cmake_minimum_required(VERSION 3.5)
project(pvr.waipu)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR})

find_package(Kodi REQUIRED)
find_package(RapidJSON 1.1.0 REQUIRED)

include_directories(${KODI_INCLUDE_DIR}/.. # Hack way with "/..", need bigger Kodi cmake rework to match right include ways
                    ${RAPIDJSON_INCLUDE_DIRS})

set(PVRWAIPU_SOURCES
                    src/Curl.cpp
                    src/Utils.cpp
                    src/HLSAllowlist.cpp
                    src/Base64.cpp
                    src/categories.cpp
                    src/WaipuData.cpp)

set(PVRWAIPU_HEADERS
                    src/Curl.h
                    src/Utils.h
                    src/HLSAllowlist.h
                    src/Base64.h
                    src/categories.h
                    src/WaipuData.h)

addon_version(pvr.waipu IPTV)
add_definitions(-DIPTV_VERSION=${IPTV_VERSION})

build_addon(pvr.waipu PVRWAIPU DEPLIBS)

include(CPack)
