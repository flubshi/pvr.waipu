cmake_minimum_required(VERSION 3.18)
project(pvr.waipu)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR})

find_package(Kodi REQUIRED)
find_package(NlohmannJson REQUIRED)

include_directories(${KODI_INCLUDE_DIR}/.. # Hack way with "/..", need bigger Kodi cmake rework to match right include ways
                    ${NLOHMANNJSON_INCLUDE_DIRS})

set(PVRWAIPU_SOURCES
                    src/Curl.cpp
                    src/Utils.cpp
                    src/HLSAllowlist.cpp
                    src/Base64.cpp
                    src/JWT.cpp
                    src/LRUChannels.cpp
                    src/MDNS.cpp
                    src/categories.cpp
                    src/WaipuData.cpp)

set(PVRWAIPU_HEADERS
                    src/Curl.h
                    src/Utils.h
                    src/HLSAllowlist.h
                    src/Base64.h
                    src/JWT.h
                    src/LRUChannels.h
                    src/MDNS.h
                    src/SynchronizedQueue.h
                    src/categories.h
                    src/WaipuData.h)

addon_version(pvr.waipu IPTV)
add_definitions(-DIPTV_VERSION=${IPTV_VERSION})

build_addon(pvr.waipu PVRWAIPU DEPLIBS)

if(WIN32)
  target_link_libraries(pvr.waipu PRIVATE ws2_32)
endif()

include(CPack)
