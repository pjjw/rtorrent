// rTorrent - BitTorrent client
// Copyright (C) 2005, Jari Sundell
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

#ifndef RTORRENT_OPTION_PARSER_H
#define RTORRENT_OPTION_PARSER_H

#include <map>
#include <string>
#include <sigc++/slot.h>

// Throws std::runtime_error upon receiving bad input.

class OptionParser {
public:
  typedef sigc::slot0<void>                                         Slot;
  typedef sigc::slot1<void, const std::string&>                     SlotString;
  typedef sigc::slot2<void, const std::string&, const std::string&> SlotStringPair;
  typedef sigc::slot2<void, int, int>                               SlotIntPair;

  OptionParser() {}
  ~OptionParser() { m_container.clear(); }

  void                insert_flag(char c, Slot s);
  void                insert_option(char c, SlotString s);
  void                insert_option_list(char c, SlotStringPair s);
  void                insert_int_pair(char c, SlotIntPair s);

  // Returns the index of the first non-option argument.
  int                 process(int argc, char** argv);

private:
  std::string         create_optstring();

  void                call(char c, const std::string& arg);
  static void         call_option_list(SlotStringPair slot, const std::string& arg);
  static void         call_int_pair(SlotIntPair slot, const std::string& arg);

  // Use pair instead?
  struct Node {
    SlotString          m_slot;
    bool                m_useOption;
  };

  typedef std::map<char, Node> Container;

  Container           m_container;
};

#endif
