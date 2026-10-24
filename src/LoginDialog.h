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

#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <string>

#include <kodi/gui/Window.h>
#include <kodi/gui/controls/Progress.h>

// Dialog for the OAuth device login. Unlike the generic Kodi progress dialog,
// it shows both login options side by side:
//  - browser login on another device with the user code
//  - "Magic Login" in the waipu.tv app (device announced via mDNS)
// A progress bar below indicates the remaining time.
//
// The interface mirrors kodi::gui::dialogs::CProgress (Open/SetPercentage/
// IsCanceled/Abort). The dialog is shown non-blocking, so the caller can keep
// polling the OAuth state on its own thread.
class ATTR_DLL_LOCAL LoginDialog : public kodi::gui::CWindow
{
public:
  LoginDialog(const std::string& heading,
              const std::string& verificationUri,
              const std::string& userCode);
  ~LoginDialog() override;

  LoginDialog(const LoginDialog&) = delete;
  LoginDialog& operator=(const LoginDialog&) = delete;

  // Shows the dialog without blocking the calling thread
  bool Open();
  // Closes the dialog; safe to call multiple times
  void Abort();

  void SetPercentage(float percentage);
  bool IsCanceled() const { return m_canceled; }

  // Callbacks from Kodi (called on the GUI thread)
  bool OnInit() override;
  bool OnClick(int controlId) override;
  bool OnAction(ADDON_ACTION actionId) override;

private:
  void Cancel();

  // control ids, see resources/skins/default/1080i/DialogWaipuLogin.xml
  static constexpr int CONTROL_PROGRESS = 20;
  static constexpr int CONTROL_BUTTON_CANCEL = 30;

  std::mutex m_mutex;
  std::unique_ptr<kodi::gui::controls::CProgress> m_progress;
  float m_percentage = 0.0f;
  bool m_closed = false;
  std::atomic<bool> m_canceled{false};
};
