/*
 *      Copyright (C) 2019 flubshi
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

#include "client.h"

#include "WaipuData.h"
#include "kodi/xbmc_pvr_dll.h"

#include <p8-platform/util/util.h>

using namespace std;
using namespace ADDON;

#ifdef TARGET_WINDOWS
#define snprintf _snprintf
#endif

ADDON_STATUS m_CurStatus = ADDON_STATUS_UNKNOWN;
WaipuData* m_data = NULL;

/* User adjustable settings are saved here.
 * Default values are defined inside client.h
 * and exported to the other source files.
 */
std::string g_strUserPath = "";
std::string g_strClientPath = "";

std::string waipuUsername;
std::string waipuPassword;
WAIPU_PROVIDER provider = WAIPU_PROVIDER_WAIPU;
std::string protocol;

CHelper_libXBMC_addon* XBMC = NULL;
CHelper_libXBMC_pvr* PVR = NULL;

extern "C"
{

  void ADDON_ReadSettings(void)
  {
    XBMC->Log(LOG_DEBUG, "waipu.tv function call: [%s]", __FUNCTION__);
    char buffer[1024];
    bool boolBuffer;
    int intBuffer;
    if (XBMC->GetSetting("username", &buffer))
    {
      waipuUsername = buffer;
    }
    if (XBMC->GetSetting("password", &buffer))
    {
      waipuPassword = buffer;
    }
    if (XBMC->GetSetting("protocol", &buffer))
    {
      protocol = buffer;
    }
    if (XBMC->GetSetting("provider_select", &intBuffer))
    {
      if (intBuffer == 0)
      {
        provider = WAIPU_PROVIDER_WAIPU;
      }
      else
      {
        provider = WAIPU_PROVIDER_O2;
      }
    }
    XBMC->Log(LOG_DEBUG, "End Readsettings");
  }

  ADDON_STATUS ADDON_Create(void* hdl, void* props)
  {
    if (!hdl || !props)
      return ADDON_STATUS_UNKNOWN;

    PVR_PROPERTIES* pvrprops = (PVR_PROPERTIES*)props;

    XBMC = new CHelper_libXBMC_addon;
    if (!XBMC->RegisterMe(hdl))
    {
      SAFE_DELETE(XBMC);
      return ADDON_STATUS_PERMANENT_FAILURE;
    }

    PVR = new CHelper_libXBMC_pvr;
    if (!PVR->RegisterMe(hdl))
    {
      SAFE_DELETE(PVR);
      SAFE_DELETE(XBMC);
      return ADDON_STATUS_PERMANENT_FAILURE;
    }

    XBMC->Log(LOG_DEBUG, "%s - Creating the waipu.tv PVR add-on", __FUNCTION__);

    m_CurStatus = ADDON_STATUS_NEED_SETTINGS;
    g_strUserPath = pvrprops->strUserPath;
    g_strClientPath = pvrprops->strClientPath;

    waipuUsername = "";
    waipuPassword = "";
    ADDON_ReadSettings();

    if (!waipuUsername.empty() && !waipuPassword.empty())
    {
      m_data = new WaipuData(waipuUsername, waipuPassword, provider);

      switch (m_data->GetLoginStatus())
      {
      case WAIPU_LOGIN_STATUS_OK:
        m_CurStatus = ADDON_STATUS_OK;
        break;
      case WAIPU_LOGIN_STATUS_NO_NETWORK:
        m_CurStatus = ADDON_STATUS_NEED_RESTART;
        XBMC->Log(LOG_ERROR, "[load data] Network issue");
        XBMC->QueueNotification(QUEUE_ERROR, XBMC->GetLocalizedString(30031));
        break;
      case WAIPU_LOGIN_STATUS_INVALID_CREDENTIALS:
        m_CurStatus = ADDON_STATUS_NEED_SETTINGS;
        XBMC->Log(LOG_ERROR, "[load data] Login invalid");
        XBMC->QueueNotification(QUEUE_ERROR, XBMC->GetLocalizedString(30032));
        break;
      case WAIPU_LOGIN_STATUS_UNKNOWN:
        XBMC->Log(LOG_ERROR, "[login status] unknown state");
        m_CurStatus = ADDON_STATUS_UNKNOWN;
        break;
      default:
        XBMC->Log(LOG_ERROR, "[login status] unhandled state");
        m_CurStatus = ADDON_STATUS_UNKNOWN;
        break;
      }
    }
    return m_CurStatus;
  }

  ADDON_STATUS ADDON_GetStatus()
  {
    XBMC->Log(LOG_DEBUG, "waipu.tv function call: [%s]", __FUNCTION__);
    return m_CurStatus;
  }

  void ADDON_Destroy()
  {
    delete m_data;
    m_CurStatus = ADDON_STATUS_UNKNOWN;
  }

  ADDON_STATUS ADDON_SetSetting(const char* settingName, const void* settingValue)
  {
    string name = settingName;

    if (name == "username")
    {
      string username = static_cast<const char*>(settingValue);
      if (username != waipuUsername)
      {
        waipuUsername = username;
        return ADDON_STATUS_NEED_RESTART;
      }
    }

    if (name == "password")
    {
      string password = static_cast<const char*>(settingValue);
      if (password != waipuPassword)
      {
        waipuPassword = password;
        return ADDON_STATUS_NEED_RESTART;
      }
    }

    if (name == "provider_select")
    {
      int tmpProviderID = *static_cast<const int*>(settingValue);
      WAIPU_PROVIDER tmpProvider;
      if (tmpProviderID == 0)
      {
        tmpProvider = WAIPU_PROVIDER_WAIPU;
      }
      else
      {
        tmpProvider = WAIPU_PROVIDER_O2;
      }

      if (tmpProvider != provider)
      {
        provider = tmpProvider;
        return ADDON_STATUS_NEED_RESTART;
      }
    }

    return ADDON_STATUS_OK;
  }

  /***********************************************************
 * PVR Client AddOn specific public library functions
 ***********************************************************/

  void OnSystemSleep() {}

  void OnSystemWake() {}

  void OnPowerSavingActivated() {}

  void OnPowerSavingDeactivated() {}

  PVR_ERROR GetAddonCapabilities(PVR_ADDON_CAPABILITIES* pCapabilities)
  {
    pCapabilities->bSupportsEPG = true;
    pCapabilities->bSupportsTV = true;
    pCapabilities->bSupportsRecordings = true;
    pCapabilities->bSupportsTimers = true;
    pCapabilities->bSupportsChannelGroups = true;

    return PVR_ERROR_NO_ERROR;
  }

  const char* GetBackendName(void)
  {
    static const char* strBackendName = "waipu.tv PVR add-on";
    return strBackendName;
  }

  const char* GetBackendVersion(void)
  {
    static string strBackendVersion = STR(IPTV_VERSION);
    return strBackendVersion.c_str();
  }

  const char* GetConnectionString(void)
  {
    static string strConnectionString = "connected";
    return strConnectionString.c_str();
  }

  const char* GetBackendHostname(void) { return ""; }

  PVR_ERROR GetDriveSpace(long long* iTotal, long long* iUsed) { return PVR_ERROR_NOT_IMPLEMENTED; }

  PVR_ERROR GetEPGForChannel(ADDON_HANDLE handle, int iChannelUid, time_t iStart, time_t iEnd)
  {

    if (m_data)
      return m_data->GetEPGForChannel(handle, iChannelUid, iStart, iEnd);

    return PVR_ERROR_SERVER_ERROR;
  }

  PVR_ERROR IsEPGTagPlayable(const EPG_TAG* tag, bool* bIsPlayable)
  {
    if (m_data)
    {
      return m_data->IsEPGTagPlayable(tag, bIsPlayable);
    }

    return PVR_ERROR_FAILED;
  }

  int GetChannelsAmount(void)
  {
    XBMC->Log(LOG_DEBUG, "waipu.tv function call: [%s]", __FUNCTION__);
    if (m_data)
      return m_data->GetChannelsAmount();

    return -1;
  }

  PVR_ERROR GetChannels(ADDON_HANDLE handle, bool bRadio)
  {
    XBMC->Log(LOG_DEBUG, "waipu.tv function call: [%s]", __FUNCTION__);
    if (m_data)
      return m_data->GetChannels(handle, bRadio);

    return PVR_ERROR_SERVER_ERROR;
  }

  void setStreamProperty(PVR_NAMED_VALUE* properties,
                         unsigned int* propertiesCount,
                         const std::string& name,
                         const std::string& value)
  {
    strncpy(properties[*propertiesCount].strName, name.c_str(),
            sizeof(properties[*propertiesCount].strName));
    strncpy(properties[*propertiesCount].strValue, value.c_str(),
            sizeof(properties[*propertiesCount].strValue));
    *propertiesCount = (*propertiesCount) + 1;
  }

  void setStreamProperties(PVR_NAMED_VALUE* properties,
                           unsigned int* propertiesCount,
                           const std::string& url)
  {
    setStreamProperty(properties, propertiesCount, PVR_STREAM_PROPERTY_STREAMURL, url);
    XBMC->Log(LOG_DEBUG, "[PLAY STREAM] url: %s", url.c_str());
    setStreamProperty(properties, propertiesCount, PVR_STREAM_PROPERTY_INPUTSTREAMADDON,
                      "inputstream.adaptive");

    if (protocol == "MPEG_DASH")
    {
      // MPEG DASH
      XBMC->Log(LOG_DEBUG, "[PLAY STREAM] dash");
      setStreamProperty(properties, propertiesCount, "inputstream.adaptive.manifest_type", "mpd");
      setStreamProperty(properties, propertiesCount, PVR_STREAM_PROPERTY_MIMETYPE,
                        "application/xml+dash");

      // get widevine license
      string license = m_data->GetLicense();
      setStreamProperty(properties, propertiesCount, "inputstream.adaptive.license_type",
                        "com.widevine.alpha");
      setStreamProperty(properties, propertiesCount, "inputstream.adaptive.license_key",
                        "https://drm.wpstr.tv/license-proxy-widevine/cenc/"
                        "|Content-Type=text%2Fxml&x-dt-custom-data=" +
                            license + "|R{SSM}|JBlicense");

      setStreamProperty(properties, propertiesCount,
                        "inputstream.adaptive.manifest_update_parameter", "full");
    }
    else
    {
      // HLS
      protocol = "HLS";
      XBMC->Log(LOG_DEBUG, "[PLAY STREAM] hls");
      setStreamProperty(properties, propertiesCount, "inputstream.adaptive.manifest_type", "hls");
      setStreamProperty(properties, propertiesCount, PVR_STREAM_PROPERTY_MIMETYPE,
                        "application/x-mpegURL");

      setStreamProperty(properties, propertiesCount,
                        "inputstream.adaptive.manifest_update_parameter", "full");
    }
  }

  PVR_ERROR GetChannelStreamProperties(const PVR_CHANNEL* channel,
                                       PVR_NAMED_VALUE* properties,
                                       unsigned int* iPropertiesCount)
  {

    string protocol_fix = protocol == "MPEG_DASH" ? "mpeg-dash" : "hls";
    string strUrl = m_data->GetChannelStreamUrl(channel->iUniqueId, protocol_fix);
    XBMC->Log(LOG_DEBUG, "Stream URL -> %s", strUrl.c_str());
    PVR_ERROR ret = PVR_ERROR_FAILED;
    if (!strUrl.empty())
    {
      *iPropertiesCount = 0;
      setStreamProperties(properties, iPropertiesCount, strUrl);
      setStreamProperty(properties, iPropertiesCount, PVR_STREAM_PROPERTY_ISREALTIMESTREAM, "true");
      ret = PVR_ERROR_NO_ERROR;
    }
    return ret;
  }

  int GetChannelGroupsAmount(void) { return m_data->GetChannelGroupsAmount(); }

  PVR_ERROR GetChannelGroups(ADDON_HANDLE handle, bool bRadio)
  {
    if (bRadio)
      return PVR_ERROR_NO_ERROR;

    if (m_data)
      return m_data->GetChannelGroups(handle);

    return PVR_ERROR_SERVER_ERROR;
  }

  PVR_ERROR GetChannelGroupMembers(ADDON_HANDLE handle, const PVR_CHANNEL_GROUP& group)
  {
    if (m_data)
      return m_data->GetChannelGroupMembers(handle, group);

    return PVR_ERROR_SERVER_ERROR;
  }

  PVR_ERROR SignalStatus(PVR_SIGNAL_STATUS& signalStatus) { return PVR_ERROR_NOT_IMPLEMENTED; }

  int GetRecordingsAmount(bool deleted) { return -1; }

  PVR_ERROR GetRecordings(ADDON_HANDLE handle, bool deleted)
  {
    XBMC->Log(LOG_DEBUG, "waipu.tv function call: [%s]", __FUNCTION__);
    if (m_data)
      return m_data->GetRecordings(handle, deleted);

    return PVR_ERROR_SERVER_ERROR;
  }

  PVR_ERROR GetRecordingStreamProperties(const PVR_RECORDING* recording,
                                         PVR_NAMED_VALUE* properties,
                                         unsigned int* iPropertiesCount)
  {
    XBMC->Log(LOG_DEBUG, "[recordings] play it...");

    string strUrl = m_data->GetRecordingURL(*recording, protocol);
    if (strUrl.empty())
    {
      return PVR_ERROR_FAILED;
    }
    *iPropertiesCount = 0;
    setStreamProperties(properties, iPropertiesCount, strUrl);
    setStreamProperty(properties, iPropertiesCount, PVR_STREAM_PROPERTY_ISREALTIMESTREAM, "true");

    return PVR_ERROR_NO_ERROR;
  }

  PVR_ERROR DeleteRecording(const PVR_RECORDING& recording)
  {
    if (m_data)
      return m_data->DeleteRecording(recording);
    return PVR_ERROR_FAILED;
  }

  void addTimerType(PVR_TIMER_TYPE types[], int idx, int attributes)
  {
    types[idx].iId = static_cast<unsigned int>(idx + 1);
    types[idx].iAttributes = static_cast<unsigned int>(attributes);
    types[idx].iPrioritiesSize = 0;
    types[idx].iLifetimesSize = 0;
    types[idx].iPreventDuplicateEpisodesSize = 0;
    types[idx].iRecordingGroupSize = 0;
    types[idx].iMaxRecordingsSize = 0;
  }

  PVR_ERROR GetTimerTypes(PVR_TIMER_TYPE types[], int* size)
  {
    //addTimerType(types, 0, PVR_TIMER_TYPE_ATTRIBUTE_NONE);
    addTimerType(types, 0,
                 PVR_TIMER_TYPE_SUPPORTS_READONLY_DELETE | PVR_TIMER_TYPE_SUPPORTS_CHANNELS |
                     PVR_TIMER_TYPE_SUPPORTS_START_TIME | PVR_TIMER_TYPE_SUPPORTS_END_TIME);
    //addTimerType(types, 1, PVR_TIMER_TYPE_IS_MANUAL);
    *size = 1;
    return PVR_ERROR_NO_ERROR;
  }

  int GetTimersAmount(void) { return -1; }

  PVR_ERROR GetTimers(ADDON_HANDLE handle)
  {
    if (m_data)
      return m_data->GetTimers(handle);

    return PVR_ERROR_SERVER_ERROR;
  }

  PVR_ERROR DeleteTimer(const PVR_TIMER& timer, bool bForceDelete)
  {
    if (m_data)
      return m_data->DeleteTimer(timer);
    return PVR_ERROR_FAILED;
  }

  PVR_ERROR AddTimer(const PVR_TIMER& timer)
  {
    if (timer.iEpgUid <= EPG_TAG_INVALID_UID)
    {
      // we currently only support epg based
      return PVR_ERROR_REJECTED;
    }
    if (m_data)
    {
      return m_data->AddTimer(timer);
    }

    return PVR_ERROR_UNKNOWN;
  }


  PVR_ERROR GetEPGTagStreamProperties(const EPG_TAG* tag,
                                      PVR_NAMED_VALUE* properties,
                                      unsigned int* iPropertiesCount)
  {
    XBMC->Log(LOG_DEBUG, "[EPG TAG] play it...");

    string strUrl = m_data->GetEPGTagURL(*tag, protocol);
    if (strUrl.empty())
    {
      return PVR_ERROR_FAILED;
    }
    *iPropertiesCount = 0;
    setStreamProperties(properties, iPropertiesCount, strUrl);
    setStreamProperty(properties, iPropertiesCount, PVR_STREAM_PROPERTY_ISREALTIMESTREAM, "true");

    return PVR_ERROR_NO_ERROR;
  }

  PVR_ERROR CallMenuHook(const PVR_MENUHOOK& menuhook, const PVR_MENUHOOK_DATA&)
  {
    return PVR_ERROR_NOT_IMPLEMENTED;
  }

  /** UNUSED API FUNCTIONS */
  PVR_ERROR OpenDialogChannelScan(void) { return PVR_ERROR_NOT_IMPLEMENTED; }
  PVR_ERROR DeleteChannel(const PVR_CHANNEL& channel) { return PVR_ERROR_NOT_IMPLEMENTED; }
  PVR_ERROR RenameChannel(const PVR_CHANNEL& channel) { return PVR_ERROR_NOT_IMPLEMENTED; }
  PVR_ERROR OpenDialogChannelSettings(const PVR_CHANNEL& channel)
  {
    return PVR_ERROR_NOT_IMPLEMENTED;
  }
  PVR_ERROR OpenDialogChannelAdd(const PVR_CHANNEL& channel) { return PVR_ERROR_NOT_IMPLEMENTED; }
  bool OpenRecordedStream(const PVR_RECORDING& recording) { return false; }
  void CloseRecordedStream(void) {}
  int ReadRecordedStream(unsigned char* pBuffer, unsigned int iBufferSize) { return 0; }
  long long SeekRecordedStream(long long iPosition, int iWhence /* = SEEK_SET */) { return 0; }
  long long LengthRecordedStream(void) { return 0; }
  void DemuxReset(void) {}
  void DemuxFlush(void) {}
  void FillBuffer(bool mode) {}
  bool OpenLiveStream(const PVR_CHANNEL&) { return false; }
  void CloseLiveStream(void) {}
  int ReadLiveStream(unsigned char* pBuffer, unsigned int iBufferSize) { return 0; }
  long long SeekLiveStream(long long iPosition, int iWhence /* = SEEK_SET */) { return -1; }
  long long LengthLiveStream(void) { return -1; }
  PVR_ERROR RenameRecording(const PVR_RECORDING& recording) { return PVR_ERROR_NOT_IMPLEMENTED; }
  PVR_ERROR SetRecordingPlayCount(const PVR_RECORDING& recording, int count)
  {
    return PVR_ERROR_NOT_IMPLEMENTED;
  }
  PVR_ERROR SetRecordingLastPlayedPosition(const PVR_RECORDING& recording, int lastplayedposition)
  {
    return PVR_ERROR_NOT_IMPLEMENTED;
  }
  int GetRecordingLastPlayedPosition(const PVR_RECORDING& recording) { return -1; }
  PVR_ERROR GetRecordingEdl(const PVR_RECORDING&, PVR_EDL_ENTRY[], int*)
  {
    return PVR_ERROR_NOT_IMPLEMENTED;
  };
  PVR_ERROR UpdateTimer(const PVR_TIMER& timer) { return PVR_ERROR_NOT_IMPLEMENTED; }
  void DemuxAbort(void) {}
  DemuxPacket* DemuxRead(void) { return NULL; }
  void PauseStream(bool bPaused) {}
  bool CanPauseStream(void) { return false; }
  bool CanSeekStream(void) { return false; }
  bool SeekTime(double, bool, double*) { return false; }
  void SetSpeed(int){};
  bool IsRealTimeStream(void) { return true; }
  PVR_ERROR UndeleteRecording(const PVR_RECORDING& recording) { return PVR_ERROR_NOT_IMPLEMENTED; }
  PVR_ERROR DeleteAllRecordingsFromTrash() { return PVR_ERROR_NOT_IMPLEMENTED; }
  PVR_ERROR SetEPGTimeFrame(int) { return PVR_ERROR_NOT_IMPLEMENTED; }
  PVR_ERROR GetDescrambleInfo(PVR_DESCRAMBLE_INFO*) { return PVR_ERROR_NOT_IMPLEMENTED; }
  PVR_ERROR SetRecordingLifetime(const PVR_RECORDING*) { return PVR_ERROR_NOT_IMPLEMENTED; }
  PVR_ERROR GetStreamProperties(PVR_STREAM_PROPERTIES*) { return PVR_ERROR_NOT_IMPLEMENTED; }
  PVR_ERROR GetStreamTimes(PVR_STREAM_TIMES*) { return PVR_ERROR_NOT_IMPLEMENTED; }
  PVR_ERROR IsEPGTagRecordable(const EPG_TAG* tag, bool* bIsRecordable)
  {
    if (m_data)
    {
      return m_data->IsEPGTagRecordable(tag, bIsRecordable);
    }

    return PVR_ERROR_FAILED;
  }
  PVR_ERROR GetEPGTagEdl(const EPG_TAG* epgTag, PVR_EDL_ENTRY edl[], int* size)
  {
    return PVR_ERROR_NOT_IMPLEMENTED;
  }
  PVR_ERROR GetStreamReadChunkSize(int* chunksize) { return PVR_ERROR_NOT_IMPLEMENTED; }

} // extern "C"
