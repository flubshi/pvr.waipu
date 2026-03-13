#pragma once

#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

class MDNS
{
public:
  MDNS();
  ~MDNS();

  MDNS(const MDNS&) = delete;
  MDNS& operator=(const MDNS&) = delete;

  void StartRegistrationService(const std::string& userCode);
  void StopRegistrationService();

  bool IsRunning() const { return m_running; }

private:
  struct DnsBuffer
  {
    std::vector<uint8_t> data;

    void U8(uint8_t v) { data.push_back(v); }
    void U16(uint16_t v) { data.push_back(v >> 8); data.push_back(v & 0xFF); }
    void U32(uint32_t v)
    {
      for (int i = 24; i >= 0; i -= 8)
        data.push_back((v >> i) & 0xFF);
    }
    void Name(const std::string& n)
    {
      for (size_t s = 0, d; s < n.size(); s = d + 1)
      {
        d = n.find('.', s);
        if (d == std::string::npos)
          d = n.size();
        const std::string label = n.substr(s, d - s);
        if (label.empty())  // trailing dot → überspringen
          continue;
        U8(static_cast<uint8_t>(label.size()));
        for (char c : label)
          U8(static_cast<uint8_t>(c));
      }
      U8(0); // root label
    }
    size_t RdlengthPlaceholder()
    {
      size_t pos = data.size();
      U16(0);
      return pos;
    }
    void PatchRdlength(size_t pos, size_t start)
    {
      const uint16_t len = static_cast<uint16_t>(data.size() - start);
      data[pos]     = len >> 8;
      data[pos + 1] = len & 0xFF;
    }
  };

  std::vector<uint8_t> BuildResponse(uint32_t ttl) const;

  static int  MakeMdnsSocket();
  static int  EphemeralPort();
  static uint32_t GetLocalIp();
  static bool IsPtrQueryForUs(const uint8_t* buf, ssize_t len);
  void        SendToMulticast(const std::vector<uint8_t>& pkt) const;
  void        SendAnnouncement(uint32_t ttl) const;

  void QueryLoop();

  static constexpr const char* MDNS_ADDR     = "224.0.0.1";
  static constexpr uint16_t    MDNS_PORT     = 5353;
  static constexpr const char* SERVICE_TYPE  = "_wlogin._tcp.local.";
  static constexpr uint32_t    ANNOUNCE_TTL  = 4500;
  static constexpr int         ANNOUNCE_SECS = 10;

  std::string             m_serviceName;
  std::string             m_userCode;
  int                     m_port{0};
  int                     m_fd{-1};
  std::atomic<bool>       m_running{false};
  std::thread             m_queryThread;
};
