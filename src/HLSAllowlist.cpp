/*
 *      Copyright (C) 2021 flubshi
 *      https://github.com/flubshi
 *
 *  This Program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This Program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with XBMC; see the file COPYING.  If not, write to
 *  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *  http://www.gnu.org/copyleft/gpl.html
 *
 */

#include "HLSAllowlist.h"

#include "kodi/tools/StringUtils.h"

#include <kodi/Filesystem.h>

HLSAllowlist::HLSAllowlist() : m_hls_allowed()
{
  LoadHLSAllowlist();
}

bool HLSAllowlist::contains(std::string channelid) const
{
  return std::find(m_hls_allowed.begin(), m_hls_allowed.end(), channelid) != m_hls_allowed.end();
}

void HLSAllowlist::LoadHLSAllowlist()
{
  const char* filePath = "special://home/addons/pvr.waipu/resources/hls_allowlist.txt";
  if (!kodi::vfs::FileExists(filePath, false))
  {
    filePath = "special://xbmc/addons/pvr.waipu/resources/hls_allowlist.txt";
  }

  if (kodi::vfs::FileExists(filePath, false))
  {
    kodi::Log(ADDON_LOG_DEBUG, "%s: Loading hls allowlist from file '%s'", __FUNCTION__, filePath);
    kodi::vfs::CFile file;
    if (!file.OpenFile(filePath, 0))
    {
      kodi::Log(ADDON_LOG_ERROR, "%s: File '%s' failed to open", __FUNCTION__, filePath);
      return;
    }

    std::string line;
    while (file.ReadLine(line))
    {
      line = kodi::tools::StringUtils::TrimRight(line);
      m_hls_allowed.push_back(line);
      kodi::Log(ADDON_LOG_DEBUG, "%s: Add channel to hls allowlist '%s'", __FUNCTION__,
                line.c_str());
    }
  }
  else
  {
    kodi::Log(ADDON_LOG_INFO, "%s: File '%s' not found", __FUNCTION__, filePath);
  }
}
