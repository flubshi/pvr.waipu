/*
 *      Copyright (C) 2005-2012 Team XBMC
 *      http://www.xbmc.org
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
 *  the Free Software Foundation, 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301 USA
 *  http://www.gnu.org/copyleft/gpl.html
 *
 */
// Code taken from pvr.zattoo

#include "categories.h"
#include <cstring>
#include <iostream>
#include <kodi/Filesystem.h>
#include <regex>

#define CATEGORIES_MAXLINESIZE    255

#if defined(_WIN32) || defined(_WIN64)
/* We are on Windows */
# define strtok_r strtok_s
#endif

Categories::Categories() :
    m_categoriesById()
{
  char *saveptr;
  LoadEITCategories();
  // Copy over
  CategoryByIdMap::const_iterator it;
  for (it = m_categoriesById.begin(); it != m_categoriesById.end(); ++it)
  {
    m_categoriesByName[it->second] = it->first;
    if (it->second.find("/") != std::string::npos)
    {
      char *categories = strdup(it->second.c_str());
      char *p = strtok_r(categories, "/", &saveptr);
      while (p != nullptr)
      {
        std::string category = p;
        m_categoriesByName[category] = it->first;
        p = strtok_r(nullptr, "/", &saveptr);
      }
      free(categories);
    }
  }
}

std::string Categories::Category(int category) const
{
  auto it = m_categoriesById.find(category);
  if (it != m_categoriesById.end())
    return it->second;
  return "";
}

int Categories::Category(const std::string& category)
{
  if (category.empty()) {
    return 0;
  }
  auto it = m_categoriesByName.find(category);
  if (it != m_categoriesByName.end())
    return it->second;
  kodi::Log(ADDON_LOG_INFO, "Missing category: %s", category.c_str());
  m_categoriesByName[category]=0;
  return 0;
}

void Categories::WriteMissingCategories()
{
  //cat ~/.kodi/temp/kodi.log| grep "MissingCategory" | cut -d"'" -f2 | sort -u > ~/fehlende_Kategorien.txt
  CategoryByNameMap::const_iterator it;
  std::string missing = "";
  for (it = m_categoriesByName.begin(); it != m_categoriesByName.end(); ++it)
  {
    kodi::Log(ADDON_LOG_DEBUG, "%s: MissingCategory='%s'", __FUNCTION__, it->first.c_str());
  }
}

void Categories::LoadEITCategories()
{
  const char *filePath = "special://home/addons/pvr.waipu/resources/eit_categories.txt";
  if (!kodi::vfs::FileExists(filePath, false)) {
    filePath = "special://xbmc/addons/pvr.waipu/resources/eit_categories.txt";
  }

  if (kodi::vfs::FileExists(filePath, false))
  {
    kodi::Log(ADDON_LOG_DEBUG, "%s: Loading EIT categories from file '%s'",
        __FUNCTION__, filePath);
    kodi::vfs::CFile file;
    if (!file.OpenFile(filePath, 0))
    {
      kodi::Log(ADDON_LOG_ERROR, "%s: File '%s' failed to open", __FUNCTION__, filePath);
      return;
    }

    std::string line;
    std::regex rgx("^ *(0x.*)*; *\"(.*)\"");
    while (file.ReadLine(line))
    {
      std::smatch matches;
      if (std::regex_search(line, matches, rgx) && matches.size() == 3)
      {
        int catId = std::stoi(matches[1].str(), nullptr, 16);
        std::string name = matches[2].str();

        m_categoriesById.insert(std::pair<int, std::string>(catId, name));
        kodi::Log(ADDON_LOG_DEBUG, "%s: Add name [%s] for category %.2X",
            __FUNCTION__, name.c_str(), catId);
      }
    }
  }
  else
  {
    kodi::Log(ADDON_LOG_INFO, "%s: File '%s' not found", __FUNCTION__, filePath);
  }
}
