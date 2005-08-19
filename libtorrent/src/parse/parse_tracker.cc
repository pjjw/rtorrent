// libTorrent - BitTorrent library
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

#include "config.h"

#include "torrent/exceptions.h"
#include "tracker/tracker_manager.h"

#include "torrent/bencode.h"
#include "parse.h"

namespace torrent {

struct _add_tracker {
  _add_tracker(int group, TrackerManager* tracker) : m_group(group), m_tracker(tracker) {}

  void operator () (const Bencode& b) {
    if (!b.is_string())
      throw bencode_error("Tracker entry not a string");
    
    m_tracker->insert(m_group, b.as_string());
  }

  int             m_group;
  TrackerManager* m_tracker;
};

struct _add_tracker_group {
  _add_tracker_group(TrackerManager* tracker) : m_group(0), m_tracker(tracker) {}

  void operator () (const Bencode& b) {
    if (!b.is_list())
      throw bencode_error("Tracker group list not a list");

    std::for_each(b.as_list().begin(), b.as_list().end(), _add_tracker(m_group++, m_tracker));
  }

  int             m_group;
  TrackerManager* m_tracker;
};

void
parse_tracker(const Bencode& b, TrackerManager* tracker) {
  if (b.has_key("announce-list") && b["announce-list"].is_list())
    std::for_each(b["announce-list"].as_list().begin(), b["announce-list"].as_list().end(),
		  _add_tracker_group(tracker));

  else if (b.has_key("announce"))
    _add_tracker(0, tracker)(b["announce"]);

  else
    throw bencode_error("Could not find any trackers");

  tracker->randomize();
}

}
