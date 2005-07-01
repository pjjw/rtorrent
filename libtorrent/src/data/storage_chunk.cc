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

#include <functional>

#include "torrent/exceptions.h"
#include "storage_chunk.h"

namespace torrent {

bool
StorageChunk::is_valid() const {
  return !empty() && std::find_if(begin(), end(), std::not1(std::mem_fun_ref(&StorageChunkPart::is_valid))) == end();
}

bool
StorageChunk::has_permissions(int prot) const {
  return std::find_if(begin(), end(), std::not1(std::bind2nd(std::mem_fun_ref(&StorageChunkPart::has_permissions), prot))) == end();
}

StorageChunk::iterator
StorageChunk::at_position(uint32_t pos) {
  if (pos >= m_size)
    throw internal_error("StorageChunk::at_position(...) tried to get StorageChunk position out of range.");

  iterator itr = std::find_if(begin(), end(), std::bind2nd(std::mem_fun_ref(&StorageChunkPart::is_contained), pos));

  if (itr == end())
    throw internal_error("StorageChunk::at_position(...) might be mangled, at_position failed horribly");

  if (itr->size() == 0)
    throw internal_error("StorageChunk::at_position(...) tried to return a node with length 0");

  return itr;
}

// Each add calls vector's reserve adding 1. This should keep
// the size of the vector at exactly what we need. Though it
// will require a few more cycles, it won't matter as we only
// rarely have more than 1 or 2 nodes.
void
StorageChunk::push_back(const MemoryChunk& c) {
  Base::reserve(Base::size() + 1);
  Base::insert(end(), StorageChunkPart(c, m_size));

  m_size += c.size();
}

void
StorageChunk::clear() {
  std::for_each(begin(), end(), std::mem_fun_ref(&StorageChunkPart::clear));

  m_size = 0;
  Base::clear();
}

uint32_t
StorageChunk::incore_length(uint32_t pos) {
  uint32_t lengthIncore = 0;
  iterator itr = at_position(pos);

  if (itr == end())
    throw internal_error("StorageChunk::incore_length(...) at end()");

  do {
    uint32_t length = itr->incore_length(pos);

    pos += length;
    lengthIncore += length;

  } while (pos == itr->get_position() + itr->size() && ++itr != end());

  return lengthIncore;
}

}
