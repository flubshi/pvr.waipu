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

#include "rapidjson/document.h"

#include <string>

class JWT
{
public:
  JWT(std::string token);
  JWT(){};

  bool isExpired(int offset = 0) const;

  std::string getToken() { return strToken; };
  int getExp() { return exp; };
  bool isInitialized() { return initialized; };
  rapidjson::Document parsedToken; // bad, I know..

private:
  std::string strToken = "";
  bool initialized = false;
  int exp = 0;
  int iat = 0;
};
