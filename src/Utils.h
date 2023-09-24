#pragma once
/*
 * taken from pvr:zattoo
 */
#include <sstream>
#include <string>
#include <vector>

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
#define timegm _mkgmtime
#endif

class Utils
{
public:
  static std::string GetFilePath(std::string strPath, bool bUserPath = true);
  static std::string UrlEncode(const std::string& string);
  static std::string ReadFile(const std::string& path);
  static time_t StringToTime(std::string timeString);
  static std::string TimeToString(time_t time);
  static int GetIDDirty(std::string str);
  static int Hash(const std::string& str);
  static int StringToInt(std::string str, int defaultValue);
  static std::string Replace(std::string str, const std::string& from, const std::string& to);
  static std::string CreateUUID();
  static bool FileDownload(std::string url, std::string targetFile);
  static bool CheckInputstreamInstalledAndEnabled(const std::string& inputstreamName);
};
