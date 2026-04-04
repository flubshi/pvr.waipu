#pragma once
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

#include <string>

class JWT
{
public:
  explicit JWT(std::string token);
  explicit JWT() {};

  bool isExpired(int offset = 0) const;

  const std::string& getToken() const { return strToken; };
  int getExp() const { return exp; };
  bool isInitialized() const { return initialized; };

  // optional field getters
  const std::string& getFieldUserHandle() const { return fieldUserHandle; };
  const std::string& getFieldSubscription() const { return fieldSubscription; };
  const std::string& getFieldEmail() const { return fieldEmail; };
  bool getFieldInstantRestart() const { return fieldInstantRestart; };
  int getFieldHoursRecording() const { return fieldHoursRecording; };

private:
  std::string strToken = "";
  bool initialized = false;
  int exp = 0;
  int iat = 0;
  // some data fields
  std::string fieldUserHandle = "";
  std::string fieldSubscription = "";
  std::string fieldEmail = "";
  bool fieldInstantRestart = false;
  int fieldHoursRecording = 0;
};
