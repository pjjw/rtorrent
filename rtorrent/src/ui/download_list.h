// rTorrent - BitTorrent client
// Copyright (C) 2005-2006, Jari Sundell
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//
// In addition, as a special exception, the copyright holders give
// permission to link the code of portions of this program with the
// OpenSSL library under certain conditions as described in each
// individual source file, and distribute linked combinations
// including the two.
//
// You must obey the GNU General Public License in all respects for
// all of the code used other than OpenSSL.  If you modify file(s)
// with this exception, you may extend this exception to your version
// of the file(s), but you are not obligated to do so.  If you do not
// wish to do so, delete this exception statement from your version.
// If you delete this exception statement from all source files in the
// program, then also delete it here.
//
// Contact:  Jari Sundell <jaris@ifi.uio.no>
//
//           Skomakerveien 33
//           3185 Skoppum, NORWAY

#ifndef RTORRENT_UI_DOWNLOAD_LIST_H
#define RTORRENT_UI_DOWNLOAD_LIST_H

#include <sigc++/slot.h>

#include "display/manager.h"

#include "element_base.h"
#include "globals.h"

class Control;

namespace core {
  class Download;
  class View;
}

namespace input {
  class Bindings;
}

namespace display {
  class Frame;
  class WindowDownloadList;
  class WindowHttpQueue;
  class WindowInput;
  class WindowLog;
  class WindowLogComplete;
}

namespace ui {

class Download;

class DownloadList : public ElementBase {
public:
  typedef display::WindowDownloadList              WList;
  typedef display::WindowLog                       WLog;
  typedef display::WindowLogComplete               WLogComplete;

  typedef sigc::slot1<void, const std::string&>    SlotOpenUri;

  typedef enum {
    DISPLAY_DOWNLOAD,
    DISPLAY_DOWNLOAD_LIST,
    DISPLAY_LOG,
    DISPLAY_STRING_LIST,
    DISPLAY_MAX_SIZE
  } Display;

  typedef enum {
    INPUT_NONE,
    INPUT_LOAD_DEFAULT,
    INPUT_LOAD_MODIFIED,
    INPUT_CHANGE_DIRECTORY,
    INPUT_COMMAND
  } Input;

  DownloadList();
  ~DownloadList();

  void                activate(display::Frame* frame, bool focus = true);
  void                disable();

  void                activate_display(Display d);

  core::View*         current_view();

  void                slot_open_uri(SlotOpenUri s) { m_slotOpenUri = s; }

private:
  DownloadList(const DownloadList&);
  void operator = (const DownloadList&);

  void                receive_view_input(Input type);
  void                receive_exit_input(Input type);

  void                receive_download_erased(core::Download* d);

  void                setup_keys();
  void                setup_input();

  Display             m_state;

  ElementBase*        m_uiArray[DISPLAY_MAX_SIZE];
  WLog*               m_windowLog;

  SlotOpenUri         m_slotOpenUri;
};

}

#endif
