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
  static double StringToDouble(const std::string& value);
  static int StringToInt(const std::string& value);
  static std::string ReadFile(const std::string& path);
  static std::vector<std::string> SplitString(const std::string& str,
                                              const char& delim,
                                              int maxParts = 0);
  static time_t StringToTime(std::string timeString);
  static std::string ltrim(std::string str, const std::string chars = "\t\n\v\f\r _");
  static int GetIDDirty(std::string str);
  static int GetChannelId(const char* strChannelName);
  static int stoiDefault(std::string str, int i);
  static bool ends_with(std::string const& haystack, std::string const& end);
  static std::string ReplaceAll(std::string str,
                                const std::string& search,
                                const std::string& replace);
};
