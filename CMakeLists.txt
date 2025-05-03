cmake_minimum_required(VERSION 4.0)
project(pvr.waipu)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR})

find_package(Kodi REQUIRED)
find_package(NlohmannJson REQUIRED)

include_directories(${NLOHMANNJSON_INCLUDE_DIRS}
                    ${KODI_INCLUDE_DIR})

set(PVRWAIPU_SOURCES
                    src/Curl.cpp
                    src/Utils.cpp
                    src/HLSAllowlist.cpp
                    src/Base64.cpp
                    src/JWT.cpp
                    src/categories.cpp
                    src/WaipuData.cpp)

set(PVRWAIPU_HEADERS
                    src/Curl.h
                    src/Utils.h
                    src/HLSAllowlist.h
                    src/Base64.h
                    src/JWT.h
                    src/categories.h
                    src/WaipuData.h)

addon_version(pvr.waipu IPTV)
add_definitions(-DIPTV_VERSION=${IPTV_VERSION})

build_addon(pvr.waipu PVRWAIPU DEPLIBS)

include(CPack)
