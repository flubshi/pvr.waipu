/*
 *      Copyright (C) 2026 flubshi
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

#include "LRUChannels.h"

#include "Utils.h"
#include "kodi/Filesystem.h"

#include <nlohmann/json.hpp>

void LRUChannels::Touch(const std::string& waipuID)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  // if already tracked, remove from current position first
  const auto it = m_set.find(waipuID);
  if (it != m_set.end())
  {
    m_list.remove(waipuID);
  }
  else
  {
    // evict least recently played channel if at capacity
    if (m_list.size() >= MAX_SIZE)
    {
      m_set.erase(m_list.back());
      m_list.pop_back();
    }
    m_set.insert(waipuID);
  }

  m_list.push_front(waipuID);
  kodi::Log(ADDON_LOG_DEBUG, "[lru] touched channel %s (list size: %zu)", waipuID.c_str(),
            m_list.size());
}

bool LRUChannels::Contains(const std::string& waipuID) const
{
  std::lock_guard<std::mutex> lock(m_mutex);
  return m_set.count(waipuID) > 0;
}

void LRUChannels::Load(const std::string& filePath)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  const std::string content = Utils::ReadFile(filePath);
  if (content.empty())
  {
    kodi::Log(ADDON_LOG_DEBUG, "[lru] no LRU channel list found at %s", filePath.c_str());
    return;
  }

  nlohmann::json arr;
  try
  {
    arr = nlohmann::json::parse(content);
  }
  catch (const nlohmann::json::parse_error&)
  {
    kodi::Log(ADDON_LOG_ERROR, "[lru] ERROR: failed to parse LRU channel list at %s",
              filePath.c_str());
    return;
  }

  if (!arr.is_array())
  {
    kodi::Log(ADDON_LOG_ERROR, "[lru] ERROR: LRU channel list is not a JSON array");
    return;
  }

  m_list.clear();
  m_set.clear();

  for (const auto& entry : arr)
  {
    if (!entry.is_string())
      continue;
    if (m_list.size() >= MAX_SIZE)
      break;
    const std::string waipuID = entry.get<std::string>();
    m_list.push_back(waipuID);
    m_set.insert(waipuID);
  }

  kodi::Log(ADDON_LOG_DEBUG, "[lru] loaded %zu channel(s) from %s", m_list.size(),
            filePath.c_str());
}

void LRUChannels::Save(const std::string& filePath) const
{
  std::lock_guard<std::mutex> lock(m_mutex);

  const nlohmann::json arr(m_list);
  const std::string content = arr.dump();

  kodi::vfs::CFile file;
  if (!file.OpenFileForWrite(filePath, true))
  {
    kodi::Log(ADDON_LOG_ERROR, "[lru] ERROR: failed to open %s for writing", filePath.c_str());
    return;
  }

  file.Write(content.data(), content.size());
  kodi::Log(ADDON_LOG_DEBUG, "[lru] saved %zu channel(s) to %s", m_list.size(), filePath.c_str());
}
