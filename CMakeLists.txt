project(pvr.waipu)

cmake_minimum_required(VERSION 2.6)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR})

enable_language(CXX)

find_package(Kodi REQUIRED)
find_package(p8-platform REQUIRED)
find_package(RapidJSON 1.0.2 REQUIRED)

include_directories(${p8-platform_INCLUDE_DIRS}
                    ${KODI_INCLUDE_DIR}
                    ${RAPIDJSON_INCLUDE_DIRS})

set(DEPLIBS ${p8-platform_LIBRARIES})

set(PVRWAIPU_SOURCES
                    src/Curl.cpp
                    src/Utils.cpp
                    src/Base64.cpp
                    src/client.cpp
                    src/WaipuData.cpp)

set(PVRWAIPU_HEADERS
                    src/Curl.h
                    src/Utils.h
                    src/Base64.h
                    src/client.h
                    src/WaipuData.h)

addon_version(pvr.waipu IPTV)
add_definitions(-DIPTV_VERSION=${IPTV_VERSION})

build_addon(pvr.waipu PVRWAIPU DEPLIBS)

include(CPack)
