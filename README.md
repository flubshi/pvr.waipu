[![Build Status](https://travis-ci.org/flubshi/pvr.waipu.svg?branch=Leia)](https://travis-ci.org/flubshi/pvr.waipu) [![Build status](https://ci.appveyor.com/api/projects/status/mak70bfs0bj78y53/branch/Matrix?svg=true)](https://ci.appveyor.com/project/flubshi/pvr-waipu/branch/Leia) [![Build Status](https://jenkins.kodi.tv/buildStatus/icon?job=flubshi%2Fpvr.waipu%2FLeia)](https://jenkins.kodi.tv/job/flubshi/job/pvr.waipu/job/Leia/)

# waipu PVR
waipu PVR client addon for [Kodi](http://kodi.tv)


## Disclaimer

This is an *unofficial* plugin. It is provided by volunteers and not related to Exaring AG or waipu.tv.
For any support regarding this plugin, please create a github issue.


## Build instructions

### Linux

1. `git clone --branch Leia https://github.com/xbmc/xbmc.git`
2. `git clone --branch Leia https://github.com/flubshi/pvr.waipu.git`
3. `cd pvr.waipu && mkdir build && cd build`
4. `cmake -DADDONS_TO_BUILD=pvr.waipu -DADDON_SRC_PREFIX=../.. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX=../../xbmc/addons -DPACKAGE_ZIP=1 ../../xbmc/cmake/addons`
5. `make`


## Useful links

* [Kodi's PVR user support](http://forum.kodi.tv/forumdisplay.php?fid=167)
* [Kodi's PVR development support](http://forum.kodi.tv/forumdisplay.php?fid=136)
