/*
 *      Copyright (C) 2026 flubshi
 *      https://github.com/flubshi
 *
 *  This Program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This Program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with XBMC; see the file COPYING.  If not, write to
 *  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *  http://www.gnu.org/copyleft/gpl.html
 *
 */

#include "MDNS.h"

#include "kodi/General.h"

#include <stdexcept>

#ifdef _WIN32
#define sock_close closesocket
#define inet_addr_compat(x) inet_addr(x) // deprecated warning unterdrücken
#pragma comment(lib, "ws2_32.lib")
#else
#define sock_close close
#define inet_addr_compat(x) inet_addr(x)
#endif

MDNS::MDNS()
{
#ifdef _WIN32
  WSADATA wsaData;
  WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

  char buf[256];
  gethostname(buf, sizeof(buf));
  m_serviceName = buf;

  // Sanitize hostname for mDNS service name:
  // alphanumeric and dash allowed (RFC 6763)
  for (char& c : m_serviceName)
  {
    if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-')
      c = '-';
  }
}

MDNS::~MDNS()
{
  StopRegistrationService();

#ifdef _WIN32
  WSACleanup();
#endif
}

void MDNS::StartRegistrationService(const std::string& userCode)
{
  if (m_running)
    return;

  m_userCode = userCode;
  m_port = EphemeralPort();
  m_fd = MakeMdnsSocket();
  m_running = true;

  SendAnnouncement(ANNOUNCE_TTL);

  // query thread for incoming PTR queries
  m_queryThread = std::thread(&MDNS::QueryLoop, this);

  kodi::Log(ADDON_LOG_INFO, "[mDNS] onServiceRegistered – name: %s | user code: %s",
            m_serviceName.c_str(), m_userCode.c_str());
}

void MDNS::StopRegistrationService()
{
  if (!m_running)
    return;

  m_running = false;

  if (m_queryThread.joinable())
    m_queryThread.join();

  if (m_fd >= 0)
  {
    SendAnnouncement(0); // TTL=0 = goodbye
    sock_close(m_fd);
    m_fd = -1;
  }

  kodi::Log(ADDON_LOG_INFO, "[mDNS] onServiceUnregistered: %s", m_serviceName.c_str());
}

void MDNS::QueryLoop()
{
  uint8_t buf[4096];

  while (m_running)
  {
    timeval tv{};
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(m_fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));

    sockaddr_in sender{};
    socklen_t senderLen = sizeof(sender);
    const ssize_t n = recvfrom(m_fd, reinterpret_cast<char*>(buf), sizeof(buf), 0,
                               reinterpret_cast<sockaddr*>(&sender), &senderLen);
    if (n <= 0)
      continue;

    if (IsPtrQueryForUs(buf, n))
    {
      kodi::Log(ADDON_LOG_DEBUG, "[mDNS] PTR query received – sending response");
      SendAnnouncement(ANNOUNCE_TTL);
    }
  }
}

std::vector<uint8_t> MDNS::BuildResponse(uint32_t ttl) const
{
  const std::string instance = m_serviceName + "." + SERVICE_TYPE; //"._wlogin._tcp.local.";
  const std::string txtEntry = "code=" + m_userCode;
  const uint32_t localIp = GetLocalIp();

  DnsBuffer buf;

  // Header
  buf.U16(0x0000); // Transaction ID
  buf.U16(0x8400); // Flags: Response + Authoritative
  buf.U16(0); // Questions
  buf.U16(3); // Answers: PTR + SRV + TXT
  buf.U16(0); // Authority
  buf.U16(1); // Additional: A-Record

  // PTR: _wlogin._tcp.local. → instance
  buf.Name(SERVICE_TYPE); // "_wlogin._tcp.local."
  buf.U16(0x000C);
  buf.U16(0x0001);
  buf.U32(ttl);
  auto p = buf.RdlengthPlaceholder();
  auto s = buf.data.size();
  buf.Name(instance);
  buf.PatchRdlength(p, s);

  // SRV: instance → hostname:port
  buf.Name(instance);
  buf.U16(0x0021);
  buf.U16(0x0001);
  buf.U32(ttl);
  p = buf.RdlengthPlaceholder();
  s = buf.data.size();
  buf.U16(0);
  buf.U16(0);
  buf.U16(static_cast<uint16_t>(m_port));
  buf.Name(m_serviceName + ".local."); // Target: hostname.local.
  buf.PatchRdlength(p, s);

  // TXT: code=<userCode>
  buf.Name(instance);
  buf.U16(0x0010);
  buf.U16(0x0001);
  buf.U32(ttl);
  p = buf.RdlengthPlaceholder();
  s = buf.data.size();
  buf.U8(static_cast<uint8_t>(txtEntry.size()));
  for (char c : txtEntry)
    buf.U8(static_cast<uint8_t>(c));
  buf.PatchRdlength(p, s);

  // A-Record: hostname.local. → IP  (Additional Record)
  buf.Name(m_serviceName + ".local.");
  buf.U16(0x0001);
  buf.U16(0x0001);
  buf.U32(ttl); // Type A, Class IN
  buf.U16(4); // RDLENGTH: 4 bytes for IPv4
  buf.U8((localIp) & 0xFF);
  buf.U8((localIp >> 8) & 0xFF);
  buf.U8((localIp >> 16) & 0xFF);
  buf.U8((localIp >> 24) & 0xFF);

  return buf.data;
}

int MDNS::MakeMdnsSocket()
{
#ifdef _WIN32
  SOCKET fds = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  int fd = static_cast<int>(fds);
#else
  int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
#endif
  if (fd < 0)
    throw std::runtime_error("mDNS: socket() failed");

  int yes = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&yes), sizeof(yes));
#ifndef _WIN32
  setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, reinterpret_cast<const char*>(&yes), sizeof(yes));
#endif

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(MDNS_PORT);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
  {
    sock_close(fd);
    throw std::runtime_error("mDNS: bind() failed");
  }

  ip_mreq mreq{};
  inet_pton(AF_INET, MDNS_ADDR, &mreq.imr_multiaddr);
  mreq.imr_interface.s_addr = htonl(INADDR_ANY);
  setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, reinterpret_cast<const char*>(&mreq), sizeof(mreq));

  uint8_t ttl = 1;
  setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, reinterpret_cast<const char*>(&ttl), sizeof(ttl));

  return fd;
}

int MDNS::EphemeralPort()
{
#ifdef _WIN32
  SOCKET fds = socket(AF_INET, SOCK_STREAM, 0);
  int fd = static_cast<int>(fds);
#else
  int fd = socket(AF_INET, SOCK_STREAM, 0);
#endif
  if (fd < 0)
    return 0;

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = 0;
  bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));

  socklen_t len = sizeof(addr);
  getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len);
  const int port = ntohs(addr.sin_port);
  sock_close(fd);
  return port;
}

uint32_t MDNS::GetLocalIp()
{
#ifdef _WIN32
  SOCKET fds = socket(AF_INET, SOCK_DGRAM, 0);
  int fd = static_cast<int>(fds);
#else
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
#endif
  if (fd < 0)
    return htonl(INADDR_LOOPBACK);

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(80);
  inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr);
  connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));

  socklen_t len = sizeof(addr);
  getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len);
  sock_close(fd);
  return addr.sin_addr.s_addr;
}

bool MDNS::IsPtrQueryForUs(const uint8_t* buf, ssize_t len)
{
  if (len < 12)
    return false;

  const uint16_t flags = (buf[2] << 8) | buf[3];
  const uint16_t questions = (buf[4] << 8) | buf[5];
  if (flags & 0x8000)
    return false;
  if (questions == 0)
    return false;

  size_t i = 12;
  std::string qname;
  while (i < static_cast<size_t>(len) && buf[i] != 0)
  {
    const uint8_t labelLen = buf[i++];
    if (i + labelLen > static_cast<size_t>(len))
      return false;
    if (!qname.empty())
      qname += '.';
    qname.append(reinterpret_cast<const char*>(&buf[i]), labelLen);
    i += labelLen;
  }
  i++;
  if (i + 4 > static_cast<size_t>(len))
    return false;

  // remove trailing dot from SERVICE_TYPE for comparison
  std::string serviceType = SERVICE_TYPE;
  if (!serviceType.empty() && serviceType.back() == '.')
    serviceType.pop_back();

  const uint16_t qtype = (buf[i] << 8) | buf[i + 1];
  return qtype == 0x000C && qname == serviceType;
}

void MDNS::SendToMulticast(const std::vector<uint8_t>& pkt) const
{
  sockaddr_in dest{};
  dest.sin_family = AF_INET;
  dest.sin_port = htons(MDNS_PORT);
  inet_pton(AF_INET, MDNS_ADDR, &dest.sin_addr);
  sendto(m_fd, reinterpret_cast<const char*>(pkt.data()), static_cast<int>(pkt.size()), 0,
         reinterpret_cast<const sockaddr*>(&dest), sizeof(dest));
}

void MDNS::SendAnnouncement(uint32_t ttl) const
{
  SendToMulticast(BuildResponse(ttl));
}
