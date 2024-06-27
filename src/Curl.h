/*
 * originally taken from pvr.zattoo
 */

#include "kodi/Filesystem.h"

#include <map>
#include <string>
#include <vector>

struct Cookie
{
  std::string host;
  std::string name;
  std::string value;
};

class Curl
{
public:
  Curl();
  virtual ~Curl();
  std::string Delete(const std::string& url, const std::string& postData, int& statusCode);
  std::string Get(const std::string& url, int& statusCode);
  std::string Post(const std::string& url, const std::string& postData, int& statusCode);
  std::string Put(const std::string& url, const std::string& postData, int& statusCode);
  void AddHeader(const std::string& name, const std::string& value);
  void AddOption(const std::string& name, const std::string& value);
  void ResetHeaders();
  virtual std::string GetCookie(const std::string& name);
  void SetCookie(const std::string& host, const std::string& name, const std::string& value);
  std::string GetLocation() { return m_location; }
  void SetRedirectLimit(int limit) { m_redirectLimit = limit; }

private:
  kodi::vfs::CFile* PrepareRequest(const std::string& action,
                                   const std::string& url,
                                   const std::string& postData);
  void ParseCookies(kodi::vfs::CFile* file, const std::string& host);
  std::string Request(const std::string& action,
                      const std::string& url,
                      const std::string& postData,
                      int& statusCode);
  std::string ParseHostname(const std::string& url);
  std::string Base64Encode(const std::string& str, bool urlEncode);
  std::map<std::string, std::string> m_headers;
  std::map<std::string, std::string> m_options;
  std::vector<Cookie> m_cookies;
  std::string m_location;
  int m_redirectLimit = 8;
};
