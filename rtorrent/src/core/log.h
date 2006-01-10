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

#ifndef RTORRENT_CORE_LOG_H
#define RTORRENT_CORE_LOG_H

#include <deque>
#include <string>
#include <sigc++/signal.h>

#include <rak/timer.h>

namespace core {

class Log : private std::deque<std::pair<rak::timer, std::string> > {
public:
  typedef std::pair<rak::timer, std::string> Type;
  typedef std::deque<Type>                     Base;
  typedef sigc::signal0<void>                  Signal;

  using Base::iterator;
  using Base::const_iterator;
  using Base::reverse_iterator;
  using Base::const_reverse_iterator;

  using Base::begin;
  using Base::end;
  using Base::rbegin;
  using Base::rend;

  using Base::empty;
  using Base::size;

  Log() : m_enabled(true) {}

  bool      is_enabled() const { return m_enabled; }

  void      enable()           { m_enabled = true; }
  void      disable()          { m_enabled = false; }

  void      push_front(const std::string& msg);

  iterator  find_older(rak::timer t);

  Signal&   signal_update() { return m_signalUpdate; }

private:
  bool      m_enabled;

  Signal    m_signalUpdate;
};

}

#endif
