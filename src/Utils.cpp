/*
 * taken from pvr:zattoo
 */

#include "Utils.h"

#include "kodi/Filesystem.h"
#include "kodi/General.h"
#include "kodi/tools/StringUtils.h"

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <sstream>

std::string Utils::GetFilePath(std::string strPath, bool bUserPath)
{
  return (bUserPath ? kodi::addon::GetUserPath(strPath) : kodi::addon::GetAddonPath(strPath));
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

std::string Utils::ReadFile(const std::string& path)
{
  kodi::vfs::CFile file;
  file.CURLCreate(path);
  if (!file.CURLCreate(path) || !file.CURLOpen(0))
  {
    kodi::Log(ADDON_LOG_ERROR, "Failed to open file [%s].", path.c_str());
    return "";
  }

  char buf[1025];
  ssize_t nbRead;
  std::string content;
  while ((nbRead = file.Read(buf, 1024)) > 0)
  {
    buf[nbRead] = 0;
    content.append(buf);
  }

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

std::string Utils::TimeToString(const time_t time)
{
  char time_str[21] = "";
  std::tm* pstm = std::localtime(&time);
  // 2019-01-20T23:59:59
  std::strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%S", pstm);
  return time_str;
}

int Utils::GetIDDirty(std::string str)
{
  // str= "_1035245078" or = "misc-rand-int-whatever"
  if (str.rfind("_", 0) == 0)
  {
    // str starts with _
    return StringToInt(kodi::tools::StringUtils::TrimLeft(str, "\t\n\v\f\r _"), 1);
  }
  return rand() % 99999 + 1;
}

int Utils::Hash(const std::string& str)
{
  const char* s = str.c_str();

  int hash = 0;
  while (*s)
    hash = ((hash << 5) + hash) + *s++;

  return std::abs(hash);
}

int Utils::StringToInt(std::string str, int defaultValue)
{
  try
  {
    return std::stoi(str);
  }
  catch (std::exception& e)
  {
    return defaultValue;
  }
}

std::string Utils::Replace(std::string str, const std::string& from, const std::string& to)
{
  // replaces the first occurrence
  // taken from: https://stackoverflow.com/questions/3418231/replace-part-of-a-string-with-another-string
  size_t start_pos = str.find(from);
  if (start_pos != std::string::npos)
    str.replace(start_pos, from.length(), to);
  return str;
}

std::string Utils::CreateUUID()
{
  // taken from pvr.dvblink
  using namespace std::chrono;

  std::string uuid;
  int64_t seed_value =
      duration_cast<milliseconds>(
          time_point_cast<milliseconds>(high_resolution_clock::now()).time_since_epoch())
          .count();
  seed_value = seed_value % 1000000000;
  srand((unsigned int)seed_value);

  //fill in uuid string from a template
  std::string template_str = "xxxxxxxx-xxxx-4xxx-8xxx-xxxxxxxxxxxx";
  for (size_t i = 0; i < template_str.size(); i++)
  {
    if (template_str[i] == 'x')
    {
      double a1 = rand();
      double a3 = RAND_MAX;
      unsigned char ch = (unsigned char)(a1 * 15 / a3);
      char buf[8];
      sprintf(buf, "%x", ch);
      uuid += buf;
    }
    else
    {
      uuid += template_str[i];
    }
  }
  return uuid;
}

bool Utils::FileDownload(std::string source, std::string target)
{
  kodi::vfs::CFile inputFile;
  if (inputFile.OpenFile(source, ADDON_READ_NO_CACHE))
  {
    kodi::vfs::CFile outputFile;
    if (outputFile.OpenFileForWrite(target, true))
    {
      char buffer[1024];
      int bytesRead = 0;
      while ((bytesRead = inputFile.Read(buffer, sizeof(buffer) - 1)) > 0)
      {
        outputFile.Write(buffer, bytesRead);
      }
      inputFile.Close();
      outputFile.Close();
      return true;
    }
  }
  return false;
}

bool Utils::CheckInputstreamInstalledAndEnabled(const std::string& inputstreamName)
{
  std::string version;
  bool enabled;

  if (kodi::IsAddonAvailable(inputstreamName, version, enabled))
  {
    if (!enabled)
    {
      std::string message = kodi::tools::StringUtils::Format(kodi::addon::GetLocalizedString(30502).c_str(), inputstreamName.c_str());
      kodi::QueueNotification(QueueMsg::QUEUE_ERROR, kodi::addon::GetLocalizedString(30500), message);
      return false;
    }
  }
  else // Not installed
  {
    std::string message = kodi::tools::StringUtils::Format(kodi::addon::GetLocalizedString(30501).c_str(), inputstreamName.c_str());
    kodi::QueueNotification(QueueMsg::QUEUE_ERROR, kodi::addon::GetLocalizedString(30500), message);
    return false;
  }

  return true;
}
