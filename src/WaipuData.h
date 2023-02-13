#pragma once
/*
 *      Copyright (C) 2019 - 2021 flubshi
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

#include "Curl.h"
#include "HLSAllowlist.h"
#include "JWT.h"
#include "categories.h"
#include "kodi/Network.h"
#include "kodi/addon-instance/PVR.h"

#include <map>
#include <mutex>
#include <vector>

// User Agent for HTTP Requests
static std::string WAIPU_USER_AGENT = "Kodi/pvr.waipu - UA will be initialized on start";
static const int WAIPU_LOGIN_FAILED_LOCK_LIMIT = 3;

enum WAIPU_PROVIDER
{
  WAIPU_PROVIDER_WAIPU = 0,
  WAIPU_PROVIDER_O2 = 1,
  WAIPU_PROVIDER_WAIPU_DEVICE = 2
};

enum class WAIPU_LOGIN_STATUS
{
  OK,
  INVALID_CREDENTIALS,
  NO_NETWORK,
  UNKNOWN
};

static const unsigned int EPG_TAG_FLAG_IS_RECORDABLE_WAIPU = (1 << 28);
static const unsigned int EPG_TAG_FLAG_INSTANT_RESTART_ALLOWED_WAIPU = (1 << 29);

class ATTR_DLL_LOCAL WaipuData : public kodi::addon::CAddonBase,
                                 public kodi::addon::CInstancePVRClient
{
public:
  WaipuData() = default;
  WaipuData(const WaipuData&) = delete;
  WaipuData(WaipuData&&) = delete;
  WaipuData& operator=(const WaipuData&) = delete;
  WaipuData& operator=(WaipuData&&) = delete;

  ADDON_STATUS Create() override;
  ADDON_STATUS SetSetting(const std::string& settingName,
                          const kodi::addon::CSettingValue& settingValue) override;

  PVR_ERROR GetCapabilities(kodi::addon::PVRCapabilities& capabilities) override;
  PVR_ERROR GetBackendName(std::string& name) override;
  PVR_ERROR GetBackendVersion(std::string& version) override;

  PVR_ERROR GetChannelsAmount(int& amount) override;
  PVR_ERROR GetChannels(bool radio, kodi::addon::PVRChannelsResultSet& results) override;

  PVR_ERROR GetChannelGroupsAmount(int& amount) override;
  PVR_ERROR GetChannelGroups(bool radio, kodi::addon::PVRChannelGroupsResultSet& results) override;
  PVR_ERROR GetChannelGroupMembers(const kodi::addon::PVRChannelGroup& group,
                                   kodi::addon::PVRChannelGroupMembersResultSet& results) override;
  PVR_ERROR GetChannelStreamProperties(
      const kodi::addon::PVRChannel& channel,
      std::vector<kodi::addon::PVRStreamProperty>& properties) override;

  PVR_ERROR GetEPGForChannel(int channelUid,
                             time_t start,
                             time_t end,
                             kodi::addon::PVREPGTagsResultSet& results) override;
  PVR_ERROR IsEPGTagRecordable(const kodi::addon::PVREPGTag& tag, bool& isRecordable) override;
  PVR_ERROR IsEPGTagPlayable(const kodi::addon::PVREPGTag& tag, bool& isPlayable) override;
  PVR_ERROR GetEPGTagStreamProperties(
      const kodi::addon::PVREPGTag& tag,
      std::vector<kodi::addon::PVRStreamProperty>& properties) override;

  PVR_ERROR GetRecordingsAmount(bool deleted, int& amount) override;
  PVR_ERROR GetRecordings(bool deleted, kodi::addon::PVRRecordingsResultSet& results) override;
  PVR_ERROR DeleteRecording(const kodi::addon::PVRRecording& recording) override;
  PVR_ERROR GetRecordingStreamProperties(
      const kodi::addon::PVRRecording& recording,
      std::vector<kodi::addon::PVRStreamProperty>& properties) override;

  PVR_ERROR GetTimerTypes(std::vector<kodi::addon::PVRTimerType>& types) override;
  PVR_ERROR GetTimersAmount(int& amount) override;
  PVR_ERROR GetTimers(kodi::addon::PVRTimersResultSet& results) override;
  PVR_ERROR DeleteTimer(const kodi::addon::PVRTimer& timer, bool forceDelete) override;
  PVR_ERROR AddTimer(const kodi::addon::PVRTimer& timer) override;
  PVR_ERROR GetDriveSpace(uint64_t& total, uint64_t& used) override;

private:
  struct WaipuChannel
  {
    int iUniqueId;
    std::string waipuID; // waipu[id]
    int iChannelNumber; //position
    std::string strChannelName; //waipu[displayName]
    std::string strIconPath; // waipu[links][rel=iconlargehd]
    bool tvfuse; // tvfuse is on demand channel
  };

  struct WaipuChannelGroup
  {
    std::string name;
    std::vector<WaipuChannel> channels;
  };

  static std::mutex mutex;
  std::string m_username;
  std::string m_password;
  std::string m_userhandle = "";
  std::string m_protocol;
  std::string m_device_id;
  WAIPU_PROVIDER m_provider;

  std::vector<WaipuChannel> m_channels;
  std::vector<WaipuChannelGroup> m_channelGroups;

  JWT m_accessToken;
  JWT m_refreshToken;
  JWT m_deviceCapabilitiesToken;

  std::string m_license;
  int m_recordings_count = 0;
  int m_timers_count = 0;
  int m_login_failed_counter = 0;
  time_t m_login_failed_locktime = 0;
  bool m_active_recordings_update = false;
  bool m_account_replay_allowed = false;
  int m_account_hours_recording = 0;
  std::vector<std::string> m_user_channels_sd;
  std::vector<std::string> m_user_channels_hd;
  WAIPU_LOGIN_STATUS m_login_status = WAIPU_LOGIN_STATUS::UNKNOWN;
  HLSAllowlist m_hls_allowlist;
  Categories m_categories;

  void ReadSettings();
  bool ParseAccessToken();

  void AddTimerType(std::vector<kodi::addon::PVRTimerType>& types, int idx, int attributes);

  std::string GetChannelStreamURL(int uniqueId,
                                  const std::string& protocol,
                                  const std::string& startTime);
  std::string GetRecordingURL(const kodi::addon::PVRRecording& recording,
                              const std::string& protocol);
  std::string GetEPGTagURL(const kodi::addon::PVREPGTag& tag, const std::string& protocol);
  std::string GetLicense();
  const std::map<std::string, std::string> GetOAuthDeviceCode(const std::string& tenant);
  const std::map<std::string, std::string> CheckOAuthState(const std::string& device_code);
  void SetStreamProperties(std::vector<kodi::addon::PVRStreamProperty>& properties,
                           const std::string& url,
                           bool realtime,
                           bool playTimeshiftBuffer,
                           const std::string& protocol);

  std::string HttpGet(const std::string& url,
                      const std::map<std::string, std::string>& headers = {});
  std::string HttpDelete(const std::string& url,
                         const std::string& postData,
                         const std::map<std::string, std::string>& headers = {});
  std::string HttpPost(const std::string& url,
                       const std::string& postData,
                       const std::map<std::string, std::string>& headers = {});
  std::string HttpRequest(const std::string& action,
                          const std::string& url,
                          const std::string& postData,
                          const std::map<std::string, std::string>& headers = {});
  std::string HttpRequestToCurl(Curl& curl,
                                const std::string& action,
                                const std::string& url,
                                const std::string& postData,
                                int& statusCode);
  bool ApiLogin();
  bool WaipuLogin();
  bool DeviceLogin(const std::string& tenant);
  bool OAuthRequest(const std::string& postData);
  bool LoadChannelData();
  bool RefreshDeviceCapabiltiesToken();
};
