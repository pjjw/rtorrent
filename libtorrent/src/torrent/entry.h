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

#ifndef LIBTORRENT_ENTRY_H
#define LIBTORRENT_ENTRY_H

#include <list>
#include <torrent/common.h>

namespace torrent {

class EntryListNode;

class Entry {
public:
  typedef std::pair<uint32_t, uint32_t> Range;

  typedef enum {
    OFF = 0,
    NORMAL,
    HIGH
  } Priority;

  Entry() : m_entry(NULL) {}
  Entry(EntryListNode* e) : m_entry(e) {}
  
  uint64_t            size_bytes();
  uint32_t            size_chunks();

  uint32_t            completed_chunks();

  uint32_t            chunk_begin();
  uint32_t            chunk_end();

  // Need this?
  //uint64_t            byte_begin();
  //uint64_t            byte_end();

  Path*               path();
  const Path*         path() const;

  // Relative to root of the torrent.
  std::string         path_str();

  // When setting the priority, Download::update_priorities() must be
  // called for it to take effect.
  Priority            priority();
  void                set_priority(Priority p);

private:
  EntryListNode*      m_entry;
};

}

#endif
