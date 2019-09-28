/*
 * originally taken from pvr.zattoo
 */
#include "Curl.h"

#include "Utils.h"
#include "client.h"

#include <utility>

using namespace std;
using namespace ADDON;

Curl::Curl() = default;

Curl::~Curl() = default;

string Curl::GetCookie(const string& name)
{
  for (const auto& cookie : cookies)
  {
    if (cookie.name == name)
      return cookie.value;
  }
  return "";
}

void Curl::SetCookie(const std::string& host, const std::string& name, const std::string& value)
{
  for (list<Cookie>::iterator i = cookies.begin(); i != cookies.end(); ++i)
  {
    if (i->host == host && i->name == name)
    {
      i->value = value;
      return;
    }
  }
  Cookie cookie;
  cookie.host = host;
  cookie.name = name;
  cookie.value = value;
  cookies.push_back(cookie);
}

void Curl::AddHeader(const string& name, const string& value)
{
  headers[name] = value;
}

void Curl::AddOption(const string& name, const string& value)
{
  options[name] = value;
}

void Curl::ResetHeaders()
{
  headers.clear();
}

string Curl::Delete(const string& url, const string& postData, int& statusCode)
{
  return Request("DELETE", url, postData, statusCode);
}

string Curl::Get(const string& url, int& statusCode)
{
  return Request("GET", url, "", statusCode);
}

string Curl::Post(const string& url, const string& postData, int& statusCode)
{
  return Request("POST", url, postData, statusCode);
}

void Curl::ParseCookies(void* file, const string& host)
{
  int numValues;
  char** cookiesPtr = XBMC->GetFilePropertyValues(file, XFILE::FILE_PROPERTY_RESPONSE_HEADER,
                                                  "set-cookie", &numValues);
  for (int i = 0; i < numValues; i++)
  {
    char* cookiePtr = cookiesPtr[i];
    if (cookiePtr && *cookiePtr)
    {
      string cookie = cookiePtr;
      std::string::size_type paramPos = cookie.find(';');
      if (paramPos != std::string::npos)
        cookie.resize(paramPos);
      vector<string> parts = Utils::SplitString(cookie, '=', 2);
      if (parts.size() != 2)
      {
        continue;
      }
      SetCookie(host, parts[0], parts[1]);
      XBMC->Log(LOG_DEBUG, "Got cookie: %s.", parts[0].c_str());
    }
  }
  XBMC->FreeStringArray(cookiesPtr, numValues);
}

string Curl::ParseHostname(const string& url)
{
  size_t pos = url.find_first_of(":");
  if (pos == string::npos)
    return "";
  string host = url.substr(pos + 3);

  size_t pos_end = host.find_first_of("://");
  if (pos_end == string::npos)
    return host;
  host = host.substr(0, pos_end);
  return host;
}

void* Curl::PrepareRequest(const string& action, const string& url, const string& postData)
{
  void* file = XBMC->CURLCreate(url.c_str());
  if (!file)
  {
    return nullptr;
  }
  XBMC->CURLAddOption(file, XFILE::CURL_OPTION_PROTOCOL, "redirect-limit", "0");
  XBMC->CURLAddOption(file, XFILE::CURL_OPTION_PROTOCOL, "customrequest", action.c_str());

  XBMC->CURLAddOption(file, XFILE::CURL_OPTION_HEADER, "acceptencoding", "gzip");

  if (!postData.empty())
  {
    string base64 = Base64Encode((const unsigned char*)postData.c_str(), postData.size(), false);
    XBMC->CURLAddOption(file, XFILE::CURL_OPTION_PROTOCOL, "postdata", base64.c_str());
  }

  for (auto const& entry : headers)
  {
    XBMC->CURLAddOption(file, XFILE::CURL_OPTION_HEADER, entry.first.c_str(), entry.second.c_str());
  }

  for (auto const& entry : options)
  {
    XBMC->CURLAddOption(file, XFILE::CURL_OPTION_PROTOCOL, entry.first.c_str(),
                        entry.second.c_str());
  }

  string host = ParseHostname(url);
  XBMC->Log(LOG_DEBUG, "Add cookies for host: %s.", host.c_str());
  string cookie_s = "";
  for (auto& cookie : cookies)
  {
    if (cookie.host != host)
      continue;
    cookie_s = cookie_s + cookie.name.c_str() + "=" + cookie.value.c_str() + "; ";
  }
  if (cookie_s.size() > 0)
    XBMC->CURLAddOption(file, XFILE::CURL_OPTION_PROTOCOL, "cookie", cookie_s.c_str());

  // we have to set "failonerror" to get error results
  XBMC->CURLAddOption(file, XFILE::CURL_OPTION_HEADER, "failonerror", "false");
  return file;
}


string Curl::Request(const string& action,
                     const string& url,
                     const string& postData,
                     int& statusCode)
{
  int remaining_redirects = redirectLimit;
  location = url;
  bool redirect;
  void* file = PrepareRequest(action, url, postData);

  do
  {
    redirect = false;
    if (file == nullptr)
    {
      statusCode = -1;
      return "";
    }

    if (!XBMC->CURLOpen(file, XFILE::READ_NO_CACHE))
    {
      statusCode = -1;
      return "";
    }

    statusCode = 200;

    // get the real statusCode
    char* tmpCode = XBMC->GetFilePropertyValue(file, XFILE::FILE_PROPERTY_RESPONSE_PROTOCOL, "");
    std::string tmpRespLine;
    tmpRespLine = tmpCode != nullptr ? tmpCode : "";
    vector<string> resp_protocol_parts = Utils::SplitString(tmpRespLine, ' ', 3);
    if (resp_protocol_parts.size() >= 2)
    {
      statusCode = Utils::stoiDefault(resp_protocol_parts[1].c_str(), -1);
      XBMC->Log(LOG_DEBUG, "HTTP response code: %i.", statusCode);
    }
    XBMC->FreeString(tmpCode);

    ParseCookies(file, ParseHostname(location));

    char* tmp = XBMC->GetFilePropertyValue(file, XFILE::FILE_PROPERTY_RESPONSE_HEADER, "Location");
    location = tmp != nullptr ? tmp : "";
    XBMC->Log(LOG_DEBUG, "Location: %s.", location.c_str());
    XBMC->FreeString(tmp);

    if (statusCode >= 301 && statusCode <= 303)
    {
      // handle redirect
      redirect = true;
      XBMC->Log(LOG_DEBUG, "redirects remaining: %i", remaining_redirects);
      remaining_redirects--;
      file = PrepareRequest("GET", location.c_str(), "");
    }
  } while (redirect && remaining_redirects >= 0);

  // read the file
  static const unsigned int CHUNKSIZE = 16384;
  char buf[CHUNKSIZE + 1];
  ssize_t nbRead;
  string body;
  while ((nbRead = XBMC->ReadFile(file, buf, CHUNKSIZE)) > 0 && ~nbRead)
  {
    buf[nbRead] = 0x0;
    body += buf;
  }

  XBMC->CloseFile(file);
  return body;
}


std::string Curl::Base64Encode(unsigned char const* in, unsigned int in_len, bool urlEncode)
{
  std::string ret;
  int i(3);
  unsigned char c_3[3];
  unsigned char c_4[4];

  const char* to_base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  while (in_len)
  {
    i = in_len > 2 ? 3 : in_len;
    in_len -= i;
    c_3[0] = *(in++);
    c_3[1] = i > 1 ? *(in++) : 0;
    c_3[2] = i > 2 ? *(in++) : 0;

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
