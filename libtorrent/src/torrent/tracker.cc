// libTorrent - BitTorrent library
// Copyright (C) 2005-2007, Jari Sundell
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

#include "config.h"

#include "tracker/tracker_http.h"
#include "tracker.h"

namespace torrent {

bool
Tracker::is_enabled() const {
  return m_tracker.second->is_enabled();
}

void
Tracker::enable() {
  m_tracker.second->enable(true);
}

void
Tracker::disable() {
  m_tracker.second->enable(false);
}

bool
Tracker::is_open() const {
  return m_tracker.second->is_busy();
}

const std::string&
Tracker::url() const {
  return m_tracker.second->url();
}

const std::string&
Tracker::tracker_id() const {
  return m_tracker.second->tracker_id();
}

Tracker::Type
Tracker::tracker_type() const {
  return static_cast<Type>(m_tracker.second->type());
}

uint32_t
Tracker::normal_interval() const {
  return m_tracker.second->normal_interval();
}

uint32_t
Tracker::min_interval() const {
  return m_tracker.second->min_interval();
}

uint64_t
Tracker::scrape_time_last() const {
  return m_tracker.second->scrape_time_last().usec();
}

uint32_t
Tracker::scrape_complete() const {
  return m_tracker.second->scrape_complete();
}

uint32_t
Tracker::scrape_incomplete() const {
  return m_tracker.second->scrape_incomplete();
}

uint32_t
Tracker::scrape_downloaded() const {
  return m_tracker.second->scrape_downloaded();
}

}
