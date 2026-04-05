/*
 *      Copyright (C) 2021 flubshi
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

#include "JWT.h"

#include "Base64.h"
#include "Utils.h"
#include "kodi/General.h"
#include "kodi/tools/StringUtils.h"

#include <chrono>
#include <vector>

#include <nlohmann/json.hpp>

using json = nlohmann::json;

JWT::JWT(std::string token)
{
  this->initialized = false;
  if (token.empty())
  {
    return;
  };
  strToken = token;
  std::vector<std::string> jwt_arr = kodi::tools::StringUtils::Split(strToken, ".", 3);
  if (jwt_arr.size() == 3)
  {
    kodi::Log(ADDON_LOG_DEBUG, "[jwt parse] middle: %s", jwt_arr.at(1).c_str());
    std::string jwt_payload = base64_decode(jwt_arr.at(1));
    kodi::Log(ADDON_LOG_DEBUG, "[jwt parse] payload: %s", jwt_payload.c_str());

    json jwtPayload;
    try
    {
      jwtPayload = json::parse(jwt_payload);
    }
    catch (const json::parse_error& e)
    {
      kodi::Log(ADDON_LOG_ERROR, "[jwt parse doc] ERROR: error while parsing json: %s", e.what());
      return;
    }

    for (const auto& field : {"iat", "exp"})
    {
      if (!jwtPayload.contains(field) || !jwtPayload[field].is_number_integer())
      {
        kodi::Log(ADDON_LOG_ERROR, "[jwt parse doc] ERROR: field '%s' missing", field);
        return;
      }
    }
    this->iat = jwtPayload["iat"].get<int>();
    this->exp = jwtPayload["exp"].get<int>();

    // parse optional fields
    if (jwtPayload.contains("userAssets"))
    {
      const auto& userAssets = jwtPayload["userAssets"];
      fieldInstantRestart = userAssets.value("instantRestart", false);
      fieldHoursRecording = userAssets.value("hoursRecording", 0);
      if (userAssets.contains("account") && userAssets["account"].contains("subscription"))
      {
        fieldSubscription = userAssets["account"]["subscription"].get<std::string>();
      }
    }
    fieldEmail = jwtPayload.value("email", "");
    this->initialized = true;
  }
}

bool JWT::isExpired(int offset) const
{
  kodi::Log(ADDON_LOG_DEBUG, "[jwt isExpired] exp: %i", exp);
  int currTime = std::chrono::duration_cast<std::chrono::seconds>(
                     std::chrono::system_clock::now().time_since_epoch())
                     .count();
  kodi::Log(ADDON_LOG_DEBUG, "[jwt isExpired] curr: %i", currTime);
  return (exp - offset) < currTime;
}