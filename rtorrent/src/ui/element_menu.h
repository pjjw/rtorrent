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

#ifndef RTORRENT_UI_ELEMENT_MENU_H
#define RTORRENT_UI_ELEMENT_MENU_H

#include <sigc++/slot.h>

#include "core/download.h"

#include "element_base.h"

namespace display {
  class WindowText;
}

namespace ui {

struct ElementMenuEntry;

class ElementMenu : public ElementBase, public std::vector<ElementMenuEntry*> {
public:
  typedef ElementMenuEntry            entry_type;
  typedef std::vector<entry_type*>    base_type;
  typedef sigc::slot0<void>           slot_type;

  typedef display::WindowText         WindowText;

  typedef uint32_t                    size_type;

  typedef base_type::value_type       value_type;
  typedef base_type::reference        reference;
  typedef base_type::iterator         iterator;
  typedef base_type::const_iterator   const_iterator;
  typedef base_type::reverse_iterator reverse_iterator;

  using base_type::empty;
  using base_type::size;

  static const size_type focus_invalid = ~size_type();

  ElementMenu();
  ~ElementMenu();

  void                activate(display::Frame* frame, bool focus = false);
  void                disable();

  // Consider returning a pointer that can be used to manipulate
  // entries, f.ex disabling them.

  void                push_back(const std::string& name,
                                const slot_type& slotSelect = slot_type(),
                                const slot_type& slotFocus = slot_type());

  void                focus_next();
  void                focus_prev();

  void                focus_select();

private:
  WindowText*         m_window;

  size_type           m_focus;
};

}

#endif
