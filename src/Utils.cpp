/*
 * taken from pvr:zattoo
 */

#include "Utils.h"

#include "client.h"
#include "p8-platform/os.h"

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <sstream>

using namespace ADDON;

std::string Utils::GetFilePath(std::string strPath, bool bUserPath)
{
  return (bUserPath ? g_strUserPath : g_strClientPath) + PATH_SEPARATOR_CHAR + strPath;
}

// http://stackoverflow.com/a/17708801
std::string Utils::UrlEncode(const std::string& value)
{
  std::ostringstream escaped;
  escaped.fill('0');
  escaped << std::hex;

  for (char c : value)
  {
    // Keep alphanumeric and other accepted characters intact
    if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
    {
      escaped << c;
      continue;
    }

    // Any other characters are percent-encoded
    escaped << '%' << std::setw(2) << int((unsigned char)c);
  }

  return escaped.str();
}

double Utils::StringToDouble(const std::string& value)
{
  std::istringstream iss(value);
  double result;

  iss >> result;

  return result;
}

int Utils::StringToInt(const std::string& value)
{
  return (int)StringToDouble(value);
}

std::vector<std::string> Utils::SplitString(const std::string& str, const char& delim, int maxParts)
{
  typedef std::string::const_iterator iter;
  iter beg = str.begin();
  std::vector<std::string> tokens;

  while (beg != str.end())
  {
    if (maxParts == 1)
    {
      tokens.emplace_back(beg, str.end());
      break;
    }
    maxParts--;
    iter temp = find(beg, str.end(), delim);
    if (beg != str.end())
      tokens.emplace_back(beg, temp);
    beg = temp;
    while ((beg != str.end()) && (*beg == delim))
      beg++;
  }

  return tokens;
}

std::string Utils::ReadFile(const std::string& path)
{
  void* file;
  file = XBMC->CURLCreate(path.c_str());
  if (!file || !XBMC->CURLOpen(file, 0))
  {
    XBMC->Log(LOG_ERROR, "Failed to open file [%s].", path.c_str());
    return "";
  }

  char buf[1025];
  ssize_t nbRead;
  std::string content;
  while ((nbRead = XBMC->ReadFile(file, buf, 1024)) > 0)
  {
    buf[nbRead] = 0;
    content.append(buf);
  }
  XBMC->CloseFile(file);

  return content;
}

time_t Utils::StringToTime(std::string timeString)
{
  // expected timeString "2019-01-20T15:40:00+0100"
  struct tm tm
  {
  };

  int year, month, day, h, m, s, tzh, tzm;
  if (sscanf(timeString.c_str(), "%d-%d-%dT%d:%d:%d%d", &year, &month, &day, &h, &m, &s, &tzh) < 7)
  {
    tzh = 0;
  }
  tzm = tzh % 100;
  tzh = tzh / 100;

  tm.tm_year = year - 1900;
  tm.tm_mon = month - 1;
  tm.tm_mday = day;
  tm.tm_hour = h - tzh;
  tm.tm_min = m - tzm;
  tm.tm_sec = s;

  time_t ret = timegm(&tm);
  return ret;
}

std::string Utils::ltrim(std::string str, const std::string chars)
{
  str.erase(0, str.find_first_not_of(chars));
  return str;
}

int Utils::GetIDDirty(std::string str)
{
  // str= "_1035245078" or = "misc-rand-int-whatever"
  if (str.rfind("_", 0) == 0)
  {
    // str starts with _
    return stoi(ltrim(str));
  }
  // dirty shit begins here:
  return rand() % 99999 + 1;
}

int Utils::GetChannelId(const char* strChannelName)
{
  int iId = 0;
  int c;
  while ((c = *strChannelName++))
    iId = ((iId << 5) + iId) + c; /* iId * 33 + c */
  return abs(iId);
}

int Utils::stoiDefault(std::string str, int i)
{
  try
  {
    return stoi(str);
  }
  catch (std::exception& e)
  {
    return i;
  }
}

bool Utils::ends_with(std::string const& haystack, std::string const& end)
{
  if (haystack.length() >= end.length())
  {
    return (0 == haystack.compare(haystack.length() - end.length(), end.length(), end));
  }
  else
  {
    return false;
  }
}


std::string Utils::ReplaceAll(std::string str,
                              const std::string& search,
                              const std::string& replace)
{
  // taken from: https://stackoverflow.com/questions/2896600/how-to-replace-all-occurrences-of-a-character-in-string
  size_t start_pos = 0;
  while ((start_pos = str.find(search, start_pos)) != std::string::npos)
  {
    str.replace(start_pos, search.length(), replace);
    start_pos += replace.length();
  }
  return str;
}
