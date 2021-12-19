/*
 * originally taken from pvr.zattoo
 */
#include "Curl.h"

#include "Utils.h"

#include "kodi/tools/StringUtils.h"

Curl::Curl() = default;

Curl::~Curl() = default;

std::string Curl::GetCookie(const std::string& name)
{
  for (const auto& cookie : m_cookies)
  {
    if (cookie.name == name)
      return cookie.value;
  }
  return "";
}

void Curl::SetCookie(const std::string& host, const std::string& name, const std::string& value)
{
  for(auto& cookie : m_cookies){
    if (cookie.host == host && cookie.name == name)
    {
      cookie.value = value;
      return;
    }
  }
  Cookie cookie;
  cookie.host = host;
  cookie.name = name;
  cookie.value = value;
  m_cookies.emplace_back(cookie);
}

void Curl::AddHeader(const std::string& name, const std::string& value)
{
  m_headers[name] = value;
}

void Curl::AddOption(const std::string& name, const std::string& value)
{
  m_options[name] = value;
}

void Curl::ResetHeaders()
{
  m_headers.clear();
}

std::string Curl::Delete(const std::string& url, const std::string& postData, int& statusCode)
{
  return Request("DELETE", url, postData, statusCode);
}

std::string Curl::Get(const std::string& url, int& statusCode)
{
  return Request("GET", url, "", statusCode);
}

std::string Curl::Post(const std::string& url, const std::string& postData, int& statusCode)
{
  return Request("POST", url, postData, statusCode);
}

void Curl::ParseCookies(kodi::vfs::CFile* file, const std::string& host)
{
  const std::vector<std::string> cookies =
      file->GetPropertyValues(ADDON_FILE_PROPERTY_RESPONSE_HEADER, "set-cookie");
  for (auto cookie : cookies)
  {
    const std::string::size_type paramPos = cookie.find(';');
    if (paramPos != std::string::npos)
      cookie.resize(paramPos);
    const std::vector<std::string> parts = kodi::tools::StringUtils::Split(cookie, "=", 2);
    if (parts.size() != 2)
      continue;
    SetCookie(host, parts[0], parts[1]);
    kodi::Log(ADDON_LOG_DEBUG, "Got cookie: %s.", parts[0].c_str());
  }
}

std::string Curl::ParseHostname(const std::string& url)
{
  const size_t pos = url.find_first_of(":");
  if (pos == std::string::npos)
    return "";

  std::string host = url.substr(pos + 3);

  const size_t pos_end = host.find_first_of("://");
  if (pos_end == std::string::npos)
    return host;

  host = host.substr(0, pos_end);
  return host;
}

kodi::vfs::CFile* Curl::PrepareRequest(const std::string& action,
                                       const std::string& url,
                                       const std::string& postData)
{
  kodi::vfs::CFile* file = new kodi::vfs::CFile;
  if (!file->CURLCreate(url))
  {
    delete file;
    return nullptr;
  }
  file->CURLAddOption(ADDON_CURL_OPTION_PROTOCOL, "redirect-limit", "0");
  file->CURLAddOption(ADDON_CURL_OPTION_PROTOCOL, "customrequest", action);

  file->CURLAddOption(ADDON_CURL_OPTION_HEADER, "acceptencoding", "gzip");

  if (!postData.empty())
  {
    const std::string base64 = Base64Encode(postData, false);
    file->CURLAddOption(ADDON_CURL_OPTION_PROTOCOL, "postdata", base64);
  }

  for (auto const& entry : m_headers)
  {
    file->CURLAddOption(ADDON_CURL_OPTION_HEADER, entry.first, entry.second);
  }

  for (auto const& entry : m_options)
  {
    file->CURLAddOption(ADDON_CURL_OPTION_PROTOCOL, entry.first, entry.second);
  }

  const std::string host = ParseHostname(url);
  kodi::Log(ADDON_LOG_DEBUG, "Add cookies for host: %s.", host.c_str());
  std::string cookie_s;
  for (auto& cookie : m_cookies)
  {
    if (cookie.host != host)
      continue;
    cookie_s = cookie_s + cookie.name + "=" + cookie.value + "; ";
  }
  if (cookie_s.size() > 0)
    file->CURLAddOption(ADDON_CURL_OPTION_PROTOCOL, "cookie", cookie_s);

  // we have to set "failonerror" to get error results
  file->CURLAddOption(ADDON_CURL_OPTION_HEADER, "failonerror", "false");
  return file;
}


std::string Curl::Request(const std::string& action,
                     const std::string& url,
                     const std::string& postData,
                     int& statusCode)
{
  int remaining_redirects = m_redirectLimit;
  m_location = url;
  bool redirect;
  kodi::vfs::CFile* file = PrepareRequest(action, url, postData);

  do
  {
    redirect = false;
    if (file == nullptr)
    {
      statusCode = -1;
      return "";
    }

    if (!file->CURLOpen(ADDON_READ_NO_CACHE))
    {
      statusCode = -1;
      return "";
    }

    statusCode = 200;

    // get the real statusCode
    const std::string tmpRespLine = file->GetPropertyValue(ADDON_FILE_PROPERTY_RESPONSE_PROTOCOL, "");
    const std::vector<std::string> resp_protocol_parts = kodi::tools::StringUtils::Split(tmpRespLine, " ", 3);

    if (resp_protocol_parts.size() >= 2)
    {
      statusCode = Utils::StringToInt(resp_protocol_parts[1], -1);
      kodi::Log(ADDON_LOG_DEBUG, "HTTP response code: %i.", statusCode);
    }

    ParseCookies(file, ParseHostname(m_location));

    m_location = file->GetPropertyValue(ADDON_FILE_PROPERTY_RESPONSE_HEADER, "Location");
    kodi::Log(ADDON_LOG_DEBUG, "Location: %s.", m_location.c_str());

    if (statusCode >= 301 && statusCode <= 303)
    {
      // handle redirect
      redirect = true;
      kodi::Log(ADDON_LOG_DEBUG, "redirects remaining: %i", remaining_redirects);
      remaining_redirects--;
      delete file;
      file = PrepareRequest("GET", m_location, "");
    }
  } while (redirect && remaining_redirects >= 0);

  // read the file
  static const unsigned int CHUNKSIZE = 16384;
  char buf[CHUNKSIZE + 1];
  ssize_t nbRead;
  std::string body;
  while ((nbRead = file->Read(buf, CHUNKSIZE)) > 0 && ~nbRead)
  {
    buf[nbRead] = 0x0;
    body += buf;
  }

  delete file;
  return body;
}


std::string Curl::Base64Encode(const std::string& str, bool urlEncode)
{
  std::string ret;
  int i = 3;
  unsigned char c_3[3];
  unsigned char c_4[4];

  const char* to_base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int len = str.size();
int curr = 0;
  while (len)
  {
    i = len > 2 ? 3 : len;
    len -= i;
    c_3[0] = str[curr++];
    c_3[1] = i > 1 ? str[curr++] : 0;
    c_3[2] = i > 2 ? str[curr++] : 0;

    c_4[0] = (c_3[0] & 0xfc) >> 2;
    c_4[1] = ((c_3[0] & 0x03) << 4) + ((c_3[1] & 0xf0) >> 4);
    c_4[2] = ((c_3[1] & 0x0f) << 2) + ((c_3[2] & 0xc0) >> 6);
    c_4[3] = c_3[2] & 0x3f;

    for (int j = 0; (j < i + 1); ++j)
    {
      if (urlEncode && to_base64[c_4[j]] == '+')
        ret += "%2B";
      else if (urlEncode && to_base64[c_4[j]] == '/')
        ret += "%2F";
      else
        ret += to_base64[c_4[j]];
    }
  }
  while ((i++ < 3))
    ret += urlEncode ? "%3D" : "=";
  return ret;
}
