[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](pvr.waipu/LICENSE.txt)
[![Build and run tests](https://github.com/flubshi/pvr.waipu/actions/workflows/build.yml/badge.svg?branch=Nexus)](https://github.com/flubshi/pvr.waipu/actions/workflows/build.yml)
[![Build Status](https://dev.azure.com/flubshi/pvr.waipu/_apis/build/status/flubshi.pvr.waipu?branchName=Nexus)](https://dev.azure.com/flubshi/pvr.waipu/_build/latest?definitionId=1&branchName=Nexus)
[![Build Status](https://jenkins.kodi.tv/buildStatus/icon?job=flubshi%2Fpvr.waipu%2FNexus)](https://jenkins.kodi.tv/job/flubshi/job/pvr.waipu/job/Nexus/)

# Waipu PVR client for Kodi
This is the waipu PVR client addon for [Kodi](https://kodi.tv). It provides Kodi integration for the German TV streaming provider waipu.tv and O2 TV. A user account for one of these providers is required to use this addon.

## Preview Images

<img src="pvr.waipu/resources/screenshots/screenshot-01.jpg" width="300" /> <img src="pvr.waipu/resources/screenshots/screenshot-02.jpg" width="300" />

## Installation

Starting with Kodi 19 - Matrix, pvr.waipu will become an official Kodi plugin and should be shipped with your installation. Current test distributions, like [Milhouse LibreELEC Nightlies](https://forum.kodi.tv/showthread.php?tid=343068) or [gmc OSMC Nightlies](https://discourse.osmc.tv/t/kodi-19-matrix-nightly-builds-for-raspberry-pi/79407) already ship pvr.waipu.


## Disclaimer

This is an *unofficial* plugin. It is provided by volunteers and not related to Exaring AG or waipu.tv.
For any support regarding this plugin, please create a github issue.


## Build instructions

### Linux

1. `git clone --branch master https://github.com/xbmc/xbmc.git`
2. `git clone --branch Nexus https://github.com/flubshi/pvr.waipu.git`
3. `cd pvr.waipu && mkdir build && cd build`
4. `cmake -DADDONS_TO_BUILD=pvr.waipu -DADDON_SRC_PREFIX=../.. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX=../../xbmc/addons -DPACKAGE_ZIP=1 ../../xbmc/cmake/addons`
5. `make`


## Useful links

* [Kodi's PVR user support](https://forum.kodi.tv/forumdisplay.php?fid=167)
* [Kodi's PVR development support](https://forum.kodi.tv/forumdisplay.php?fid=136)
