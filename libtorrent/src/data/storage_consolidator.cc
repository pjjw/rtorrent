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
// Contact:  Jari Sundell <jaris@ifi.uio.no>
//
//           Skomakerveien 33
//           3185 Skoppum, NORWAY

#include "config.h"

#include <algorithm>
#include <functional>

#include "torrent/exceptions.h"
#include "file.h"
#include "storage_consolidator.h"

namespace torrent {

StorageConsolidator::~StorageConsolidator() {
  close();
}

void StorageConsolidator::add_file(File* file, uint64_t size) {
  if (sizeof(off_t) != 8)
    throw internal_error("sizeof(off_t) != 8");

  if (size + m_size < m_size)
    throw internal_error("Sum of files added to StorageConsolidator overflowed 64bit");

  if (file == NULL)
    throw internal_error("StorageConsolidator::add_file received a File NULL pointer");

  Base::push_back(StorageFile(file, m_size, size));
  m_size += size;
}

bool StorageConsolidator::resize() {
  return std::find_if(begin(), end(), std::not1(std::mem_fun_ref(&StorageFile::resize_file)))
    == end();
}
					   
void StorageConsolidator::close() {
  std::for_each(begin(), end(), std::mem_fun_ref(&StorageFile::clear));

  Base::clear();
  m_size = 0;
}

void
StorageConsolidator::sync() {
  std::for_each(begin(), end(), std::mem_fun_ref(&StorageFile::sync));
}

void StorageConsolidator::set_chunksize(uint32_t size) {
  if (size == 0)
    throw internal_error("Tried to set StorageConsolidator's chunksize to zero");

  m_chunksize = size;
}

bool StorageConsolidator::get_chunk(StorageChunk& chunk, uint32_t b, int prot) {
  chunk.clear();

  uint64_t pos = b * (uint64_t)m_chunksize;
  uint64_t last = std::min((b + 1) * (uint64_t)m_chunksize, m_size);

  if (pos >= m_size)
    throw internal_error("Tried to access chunk out of range in StorageConsolidator");

  iterator itr = std::find_if(begin(), end(), std::bind2nd(std::mem_fun_ref(&StorageFile::is_valid_position), pos));

  while (pos != last) {
    if (itr == end())
      throw internal_error("StorageConsolidator could not find a valid file for chunk");

    uint64_t offset = pos - itr->position();
    uint32_t length = std::min(last - pos, itr->size() - offset);

    if (length == 0)
      throw internal_error("StorageConsolidator::get_chunk caught a piece with 0 lenght");

    if (length > m_chunksize)
      throw internal_error("StorageConsolidator::get_chunk caught an excessively large piece");

    MemoryChunk mc = itr->file()->get_chunk(offset, length, prot, MemoryChunk::map_shared);

    if (!mc.is_valid()) {
      // Require the caller to clear?
      chunk.clear();

      return false;
    }

    chunk.push_back(mc);

    pos += length;
    ++itr;
  }

  if (chunk.get_size() != last - b * (uint64_t)m_chunksize)
    throw internal_error("StorageConsolidator::get_chunk didn't get a chunk with the correct size");

  return true;
}

}

