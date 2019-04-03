/*
 * taken from pvr:zattoo
 */

#include "Utils.h"

#include <algorithm>
#include <iomanip>
#include <iterator>
#include <sstream>

#include <iostream>

#include "p8-platform/os.h"

#include "client.h"

using namespace ADDON;

std::string Utils::GetFilePath(std::string strPath, bool bUserPath)
{
  return (bUserPath ? g_strUserPath : g_strClientPath) + PATH_SEPARATOR_CHAR
      + strPath;
}

// http://stackoverflow.com/a/17708801
std::string Utils::UrlEncode(const std::string &value)
{
  std::ostringstream escaped;
  escaped.fill('0');
  escaped << std::hex;

  for (char c : value) {
      // Keep alphanumeric and other accepted characters intact
    if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
    {
      escaped << c;
      continue;
    }

    // Any other characters are percent-encoded
    escaped << '%' << std::setw(2) << int((unsigned char) c);
  }

  return escaped.str();
}

double Utils::StringToDouble(const std::string &value)
{
  std::istringstream iss(value);
  double result;

  iss >> result;

  return result;
}

int Utils::StringToInt(const std::string &value)
{
  return (int) StringToDouble(value);
}

std::vector<std::string> Utils::SplitString(const std::string &str,
    const char &delim, int maxParts)
{
  typedef std::string::const_iterator iter;
  iter beg = str.begin();
  std::vector < std::string > tokens;

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
  struct tm etm;
  strptime(timeString.c_str(), "%Y-%m-%dT%H:%M:%S%z", &etm);
  return mktime(&etm)+0*3600; // +60*60 = dirty hack (0*=Summer, 1*=Winter)
}

std::string Utils::ltrim(std::string str, const std::string chars)
{
    str.erase(0, str.find_first_not_of(chars));
    return str;
}

int Utils::GetIDDirty(std::string str)
{
	// str= "_1035245078" or = "misc-rand-int-whatever"
	if (str.rfind("_", 0) == 0) {
		// str starts with _
		return stoi(ltrim(str));
	}
	// dirty shit begins here:
	return rand() % 99999 + 1;
}
