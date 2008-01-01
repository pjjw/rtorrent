// rTorrent - BitTorrent client
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

#include <rak/file_stat.h>
#include <rak/path.h>
#include <torrent/exceptions.h>

#include "file_status_cache.h"

namespace utils {

bool
FileStatusCache::insert(const std::string& path, int flags) {
  rak::file_stat fs;

  // Should we expand somewhere else? Problem is it adds a lot of junk
  // to the start of the paths added to the cache, causing more work
  // during search, etc.
  if (!fs.update(rak::path_expand(path)))
    return false;

  std::pair<iterator, bool> result = base_type::insert(value_type(path, file_status()));

  // Return false if the file hasn't been modified since last time. We
  // use 'equal to' instead of 'greater than' since the file might
  // have been replaced by another file, and thus should be re-tried.
  if (!result.second && result.first->second.m_mtime == (uint32_t)fs.modified_time())
    return false;

  result.first->second.m_flags = 0;
  result.first->second.m_mtime = fs.modified_time();

  return true;
}

void
FileStatusCache::prune() {
  iterator itr = begin();

  while (itr != end()) {
    rak::file_stat fs;
    iterator tmp = itr++;

    if (!fs.update(rak::path_expand(tmp->first)) || tmp->second.m_mtime != (uint32_t)fs.modified_time())
      base_type::erase(tmp);
  }
}

}
