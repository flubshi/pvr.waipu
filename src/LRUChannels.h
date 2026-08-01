#pragma once
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

#include <list>
#include <mutex>
#include <string>
#include <unordered_set>

// Tracks the last MAX_SIZE played channels by waipu station ID.
// Used to enable EPG detail fetching for recently played channels,
// analogous to the favorite channels mechanism.
class LRUChannels
{
public:
  // Maximum number of channels tracked in the LRU list
  static constexpr size_t MAX_SIZE = 12;

  // Move waipuID to the front of the list (most recently played).
  // If the channel is not yet in the list, it is added. If the list
  // is at capacity, the least recently played channel is evicted.
  void Touch(const std::string& waipuID);

  // Returns true if waipuID is currently in the LRU list.
  bool Contains(const std::string& waipuID) const;

  // Loads the LRU list from a JSON file at filePath.
  // Silently does nothing if the file does not exist or cannot be parsed.
  void Load(const std::string& filePath);

  // Saves the current LRU list as a JSON array to filePath.
  void Save(const std::string& filePath) const;

private:
  mutable std::mutex m_mutex;
  std::list<std::string> m_list; // front = most recently played
  std::unordered_set<std::string> m_set; // O(1) membership check
};
