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

#include "LoginDialog.h"

#include "kodi/General.h"

LoginDialog::LoginDialog(const std::string& heading,
                         const std::string& verificationUri,
                         const std::string& userCode)
  : kodi::gui::CWindow("DialogWaipuLogin.xml", "default", true)
{
  // static texts are taken from strings.po directly in the skin xml,
  // dynamic values are passed as window properties
  SetProperty("heading", heading);
  SetProperty("verification_uri", verificationUri);
  SetProperty("user_code", userCode);
}

LoginDialog::~LoginDialog()
{
  Abort();
}

bool LoginDialog::Open()
{
  kodi::Log(ADDON_LOG_DEBUG, "[LoginDialog] open");
  return Show();
}

void LoginDialog::Abort()
{
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_closed)
      return;
    m_closed = true;
    // do not touch the gui control anymore once the dialog gets closed
    m_progress.reset();
  }
  kodi::Log(ADDON_LOG_DEBUG, "[LoginDialog] close");
  Close();
}

void LoginDialog::SetPercentage(float percentage)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_percentage = percentage;
  // the control is created on window init, until then only the value is stored
  if (m_progress)
    m_progress->SetPercentage(m_percentage);
}

void LoginDialog::Cancel()
{
  kodi::Log(ADDON_LOG_DEBUG, "[LoginDialog] canceled by user");
  m_canceled = true;
  Abort();
}

bool LoginDialog::OnInit()
{
  std::lock_guard<std::mutex> lock(m_mutex);
  if (m_closed)
    return true;

  m_progress = std::make_unique<kodi::gui::controls::CProgress>(this, CONTROL_PROGRESS);
  m_progress->SetPercentage(m_percentage);
  return true;
}

bool LoginDialog::OnClick(int controlId)
{
  if (controlId == CONTROL_BUTTON_CANCEL)
  {
    Cancel();
    return true;
  }
  return false;
}

bool LoginDialog::OnAction(ADDON_ACTION actionId)
{
  switch (actionId)
  {
    case ADDON_ACTION_PREVIOUS_MENU:
    case ADDON_ACTION_NAV_BACK:
      Cancel();
      return true;
    default:
      break;
  }
  return false;
}
