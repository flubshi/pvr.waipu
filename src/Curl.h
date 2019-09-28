/*
 * originally taken from pvr.zattoo
 */
#include <list>
#include <map>
#include <string>

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
  virtual std::string Delete(const std::string& url, const std::string& postData, int& statusCode);
  virtual std::string Get(const std::string& url, int& statusCode);
  virtual std::string Post(const std::string& url, const std::string& postData, int& statusCode);
  virtual void AddHeader(const std::string& name, const std::string& value);
  virtual void AddOption(const std::string& name, const std::string& value);
  virtual void ResetHeaders();
  virtual std::string GetCookie(const std::string& name);
  virtual void SetCookie(const std::string& host,
                         const std::string& name,
                         const std::string& value);
  virtual std::string GetLocation() { return location; }
  virtual void SetRedirectLimit(int limit) { redirectLimit = limit; }

private:
  virtual void* PrepareRequest(const std::string& action,
                               const std::string& url,
                               const std::string& postData);
  virtual void ParseCookies(void* file, const std::string& host);
  virtual std::string Request(const std::string& action,
                              const std::string& url,
                              const std::string& postData,
                              int& statusCode);
  virtual std::string ParseHostname(const std::string& url);
  std::string Base64Encode(unsigned char const* in, unsigned int in_len, bool urlEncode);
  std::map<std::string, std::string> headers;
  std::map<std::string, std::string> options;
  std::list<Cookie> cookies;
  std::string location;
  int redirectLimit = 8;
};
