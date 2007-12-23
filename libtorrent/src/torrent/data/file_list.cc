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

#include <algorithm>
#include <cstring>
#include <functional>
#include <limits>
#include <memory>
#include <set>
#include <rak/error_number.h>
#include <rak/file_stat.h>
#include <rak/fs_stat.h>
#include <rak/functional.h>

#include "data/chunk.h"
#include "data/memory_chunk.h"
#include "data/socket_file.h"

#include "torrent/exceptions.h"
#include "torrent/path.h"

#include "file.h"
#include "file_list.h"
#include "file_manager.h"
#include "manager.h"
#include "piece.h"

namespace torrent {

void
verify_file_list(const FileList* fl) {
  if (fl->empty())
    throw internal_error("verify_file_list() 1.");

  if ((*fl->begin())->match_depth_prev() != 0 || (*fl->rbegin())->match_depth_next() != 0)
    throw internal_error("verify_file_list() 2.");

  for (FileList::const_iterator itr = fl->begin(), last = fl->end() - 1; itr != last; itr++)
    if ((*itr)->match_depth_next() != (*(itr + 1))->match_depth_prev() ||
        (*itr)->match_depth_next() >= (*itr)->path()->size())
      throw internal_error("verify_file_list() 3.");
}

FileList::FileList() :
  m_isOpen(false),

  m_torrentSize(0),
  m_chunkSize(0),
  m_maxFileSize((uint64_t)64 << 30) {
}

FileList::~FileList() {
  // Can we skip close()?
  close();

  std::for_each(begin(), end(), rak::call_delete<File>());

  base_type::clear();
  m_torrentSize = 0;
}

bool
FileList::is_valid_piece(const Piece& piece) const {
  return
    piece.index() < size_chunks() &&
    piece.length() != 0 &&

    // Make sure offset does not overflow 32 bits.
    piece.offset() + piece.length() >= piece.offset() &&
    piece.offset() + piece.length() <= chunk_index_size(piece.index());
}

bool
FileList::is_multi_file() const {
  // Currently only check if we got just one file. In the future this
  // should be a bool, which will be set based on what flags are
  // passed when the torrent was loaded.
  return m_isMultiFile;
}

uint64_t
FileList::completed_bytes() const {
  // Chunk size needs to be cast to a uint64_t for the below to work.
  uint64_t cs = chunk_size();

  if (m_bitfield.empty())
    return m_bitfield.is_all_set() ? size_bytes() : (completed_chunks() * cs);

  if (!m_bitfield.get(size_chunks() - 1) || size_bytes() % cs == 0) {
    // The last chunk is not done, or the last chunk is the same size
    // as the others.
    return completed_chunks() * cs;

  } else {
    if (completed_chunks() == 0)
      throw internal_error("FileList::bytes_completed() completed_chunks() == 0.");

    return (completed_chunks() - 1) * cs + size_bytes() % cs;
  }
}

uint64_t
FileList::left_bytes() const {
  uint64_t left = size_bytes() - completed_bytes();

  if (left > ((uint64_t)1 << 60))
    throw internal_error("FileList::bytes_left() is too large."); 

  if (completed_chunks() == size_chunks() && left != 0)
    throw internal_error("FileList::bytes_left() has an invalid size."); 

  return left;
}

uint32_t
FileList::chunk_index_size(uint32_t index) const {
  if (index + 1 != size_chunks() || size_bytes() % chunk_size() == 0)
    return chunk_size();
  else
    return size_bytes() % chunk_size();
}

void
FileList::set_root_dir(const std::string& path) {
  if (is_open())
    throw input_error("Tried to change the root directory on an open download.");

  std::string::size_type last = path.find_last_not_of('/');

  if (last == std::string::npos)
    m_rootDir = ".";
  else
    m_rootDir = path.substr(0, last + 1);
}

void
FileList::set_max_file_size(uint64_t size) {
  if (is_open())
    throw input_error("Tried to change the max file size for an open download.");

  m_maxFileSize = size;
}

// This function should really ensure that we arn't dealing files
// spread over multiple mount-points.
uint64_t
FileList::free_diskspace() const {
  uint64_t freeDiskspace = std::numeric_limits<uint64_t>::max();

  for (path_list::const_iterator itr = m_indirectLinks.begin(), last = m_indirectLinks.end(); itr != last; ++itr) {
    rak::fs_stat stat;

    if (!stat.update(*itr))
      continue;

    freeDiskspace = std::min<uint64_t>(freeDiskspace, stat.bytes_avail());
  }

  return freeDiskspace != std::numeric_limits<uint64_t>::max() ? freeDiskspace : 0;
}

FileList::iterator_range
FileList::split(iterator position, split_type* first, split_type* last) {
  if (is_open())
    throw internal_error("FileList::split(...) is_open().");
  
  if (first == last || position == end())
    throw internal_error("FileList::split(...) invalid arguments.");

  if (position != begin())
    (*(position - 1))->set_match_depth_next(0);

  if (position + 1 != end())
    (*(position + 1))->set_match_depth_prev(0);

  File* oldFile = *position;

  uint64_t offset = oldFile->offset();
  size_type index = std::distance(begin(), position);
  size_type length = std::distance(first, last);

  base_type::insert(position, length - 1, NULL);
  position = begin() + index;

  iterator itr = position;

  while (first != last) {
    File* newFile = new File();

    newFile->set_offset(offset);
    newFile->set_size_bytes(first->first);
    newFile->set_range(m_chunkSize);
    *newFile->mutable_path() = first->second;

    offset += first->first;
    *itr = newFile;

    itr++;
    first++;
  }

  if (offset != oldFile->offset() + oldFile->size_bytes())
    throw internal_error("FileList::split(...) split size does not match the old size.");

  delete oldFile;
  return iterator_range(position, itr);
}

FileList::iterator
FileList::merge(iterator first, iterator last, const Path& path) {
  File* newFile = new File;

  // Set the path before deleting any iterators in case it refers to
  // one of the objects getting deleted.
  *newFile->mutable_path() = path;

  if (first == last) {
    if (first == end())
      newFile->set_offset(m_torrentSize);
    else
      newFile->set_offset((*first)->offset());

    first = base_type::insert(first, newFile);

  } else {
    newFile->set_offset((*first)->offset());

    for (iterator itr = first; itr != last; ++itr) {
      newFile->set_size_bytes(newFile->size_bytes() + (*itr)->size_bytes());
      delete *itr;
    }

    first = base_type::erase(first + 1, last) - 1;
    *first = newFile;
  }

  newFile->set_range(m_chunkSize);

  if (first == begin())
    newFile->set_match_depth_prev(0);
  else
    File::set_match_depth(*(first - 1), newFile);

  if (first + 1 == end())
    newFile->set_match_depth_next(0);
  else
    File::set_match_depth(newFile, *(first + 1));

  return first;
}

// If the user supplies an invalid range, it will bork in weird ways.
void
FileList::update_paths(iterator first, iterator last) {
  // Check if we're open?

  if (first == last)
    return;

  if (first != begin())
    File::set_match_depth(*(first - 1), *first);

  while (first != last && ++first != end())
    File::set_match_depth(*(first - 1), *first);

  verify_file_list(this);
}

bool
FileList::make_root_path() {
  if (!is_open())
    return false;

  return ::mkdir(m_rootDir.c_str(), 0777) == 0 || errno == EEXIST;
}

bool
FileList::make_all_paths() {
  if (!is_open())
    return false;

  Path dummyPath;
  const Path* lastPath = &dummyPath;

  for (iterator itr = begin(), last = end(); itr != last; ++itr) {
    File* entry = *itr;

    // No need to create directories if the entry has already been
    // opened.
    if (entry->is_open())
      continue;

    if (entry->path()->empty())
      throw storage_error("Found an empty filename.");

    Path::const_iterator lastPathItr   = lastPath->begin();
    Path::const_iterator firstMismatch = entry->path()->begin();

    // Couldn't find a suitable stl algo, need to write my own.
    while (firstMismatch != entry->path()->end() && lastPathItr != lastPath->end() && *firstMismatch == *lastPathItr) {
      lastPathItr++;
      firstMismatch++;
    }

    rak::error_number::clear_global();

    make_directory(entry->path()->begin(), entry->path()->end(), firstMismatch);
    
    lastPath = entry->path();
  }

  return true;
}

// Initialize FileList and add a dummy file that may be split into
// multiple files.
void
FileList::initialize(uint64_t torrentSize, uint32_t chunkSize) {
  if (sizeof(off_t) != 8)
    throw internal_error("Last minute panic; sizeof(off_t) != 8.");

  if (chunkSize == 0)
    throw internal_error("FileList::initialize() chunk_size() == 0.");

  m_chunkSize = chunkSize;
  m_torrentSize = torrentSize;
  m_rootDir = ".";

  m_bitfield.set_size_bits((size_bytes() + chunk_size() - 1) / chunk_size());

  File* newFile = new File();

  newFile->set_offset(0);
  newFile->set_size_bytes(torrentSize);
  newFile->set_range(m_chunkSize);

  base_type::push_back(newFile);
}

struct file_list_cstr_less {
  bool operator () (const char* c1, const char* c2) const {
    return std::strcmp(c1, c2) < 0;
  }
};

void
FileList::open(int flags) {
  typedef std::set<const char*, file_list_cstr_less> path_set;

  if (m_rootDir.empty())
    throw internal_error("FileList::open() m_rootDir.empty().");

  m_indirectLinks.push_back(m_rootDir);

  Path lastPath;
  path_set pathSet;

  try {
    if (!(flags & open_no_create) && !make_root_path())
      throw storage_error("Could not create directory '" + m_rootDir + "': " + std::strerror(errno));
  
    for (iterator itr = begin(), last = end(); itr != last; ++itr) {
      File* entry = *itr;

      // We no longer consider it an error to open a previously opened
      // FileList as we now use the same function to create
      // non-existent files.
      //
      // Since m_isOpen is set, we know root dir wasn't changed, thus
      // we can keep the previously opened file.
      if (entry->is_open())
        continue;
      
      // Update the path during open so that any changes to root dir
      // and file paths are properly handled.
      if (entry->path()->back().empty())
        entry->set_frozen_path(std::string());
      else
        entry->set_frozen_path(m_rootDir + entry->path()->as_string());

      if (!pathSet.insert(entry->frozen_path().c_str()).second)
        throw storage_error("Found a duplicate filename.");

      if (entry->size_bytes() > m_maxFileSize)
        throw storage_error("Found a file exceeding max file size.");

      if (entry->path()->empty())
        throw storage_error("Found an empty filename.");

      // Handle directory creation outside of open_file, so we can do
      // it here if necessary.

      entry->set_flags_protected(File::flag_active);

      if (!open_file(&*entry, lastPath, flags)) {
        // This needs to check if the error was due to open_no_create
        // being set or not.
        if (!(flags & open_no_create))
          // Also check if open_require_all_open is set.
          throw storage_error("Could not open file \"" + m_rootDir + entry->path()->as_string() + "\": " + rak::error_number::current().c_str());

        // Don't set the lastPath as we haven't created the directory.
        continue;
      }

      lastPath = *entry->path();
    }

  } catch (local_error& e) {
    for (iterator itr = begin(), last = end(); itr != last; ++itr) {
      (*itr)->unset_flags_protected(File::flag_active);
      manager->file_manager()->close(*itr);
    }

    // Set to false here in case we tried to open the FileList for the
    // second time.
    m_isOpen = false;
    throw;
  }

  m_isOpen = true;
}

void
FileList::close() {
  if (!is_open())
    return;

  for (iterator itr = begin(), last = end(); itr != last; ++itr) {
    (*itr)->unset_flags_protected(File::flag_active);
    manager->file_manager()->close(*itr);
  }

  m_isOpen = false;
  m_indirectLinks.clear();
}

void
FileList::make_directory(Path::const_iterator pathBegin, Path::const_iterator pathEnd, Path::const_iterator startItr) {
  std::string path = m_rootDir;

  while (pathBegin != pathEnd) {
    path += "/" + *pathBegin;

    if (pathBegin++ != startItr)
      continue;

    startItr++;

    rak::file_stat fileStat;

    if (fileStat.update_link(path) &&
        fileStat.is_link() &&
        std::find(m_indirectLinks.begin(), m_indirectLinks.end(), path) == m_indirectLinks.end())
      m_indirectLinks.push_back(path);

    if (pathBegin == pathEnd)
      break;

    if (::mkdir(path.c_str(), 0777) != 0 && errno != EEXIST)
      throw storage_error("Could not create directory '" + path + "': " + std::strerror(errno));
  }
}

bool
FileList::open_file(File* node, const Path& lastPath, int flags) {
  rak::error_number::clear_global();

  if (!(flags & open_no_create)) {
    const Path* path = node->path();

    Path::const_iterator lastItr = lastPath.begin();
    Path::const_iterator firstMismatch = path->begin();

    // Couldn't find a suitable stl algo, need to write my own.
    while (firstMismatch != path->end() && lastItr != lastPath.end() && *firstMismatch == *lastItr) {
      lastItr++;
      firstMismatch++;
    }

    make_directory(path->begin(), path->end(), firstMismatch);
  }

  // Some torrents indicate an empty directory by having a path with
  // an empty last element. This entry must be zero length.
  if (node->path()->back().empty())
    return node->size_bytes() == 0;

  rak::file_stat fileStat;

  if (fileStat.update(node->frozen_path()) &&
      !fileStat.is_regular() && !fileStat.is_link()) {
    // Might also bork on other kinds of file types, but there's no
    // suitable errno for all cases.
    rak::error_number::set_global(rak::error_number::e_isdir);
    return false;
  }

  return
    node->prepare(MemoryChunk::prot_read | MemoryChunk::prot_write, (flags & open_no_create ? 0 : SocketFile::o_create)) ||
    node->prepare(MemoryChunk::prot_read, 0);
}

MemoryChunk
FileList::create_chunk_part(FileList::iterator itr, uint64_t offset, uint32_t length, int prot) {
  offset -= (*itr)->offset();
  length = std::min<uint64_t>(length, (*itr)->size_bytes() - offset);

  if (offset < 0)
    throw internal_error("FileList::chunk_part(...) caught a negative offset");

  // Check that offset != length of file.

  if (!(*itr)->prepare(prot))
    return MemoryChunk();

  return SocketFile((*itr)->file_descriptor()).create_chunk(offset, length, prot, MemoryChunk::map_shared);
}

Chunk*
FileList::create_chunk(uint64_t offset, uint32_t length, int prot) {
  if (offset + length > m_torrentSize)
    throw internal_error("Tried to access chunk out of range in FileList");

  std::auto_ptr<Chunk> chunk(new Chunk);

  for (iterator itr = std::find_if(begin(), end(), std::bind2nd(std::mem_fun(&File::is_valid_position), offset)); length != 0; ++itr) {

    if (itr == end())
      throw internal_error("FileList could not find a valid file for chunk");

    if ((*itr)->size_bytes() == 0)
      continue;

    MemoryChunk mc = create_chunk_part(itr, offset, length, prot);

    if (!mc.is_valid())
      return NULL;

    if (mc.size() == 0)
      throw internal_error("FileList::create_chunk(...) mc.size() == 0.");

    if (mc.size() > length)
      throw internal_error("FileList::create_chunk(...) mc.size() > length.");

    chunk->push_back(ChunkPart::MAPPED_MMAP, mc);

    offset += mc.size();
    length -= mc.size();
  }

  if (chunk->empty())
    return NULL;

  return chunk.release();
}

Chunk*
FileList::create_chunk_index(uint32_t index, int prot) {
  return create_chunk((uint64_t)index * chunk_size(), chunk_index_size(index), prot);
}

void
FileList::mark_completed(uint32_t index) {
  if (m_bitfield.get(index))
    throw internal_error("FileList::mark_completed(...) received a chunk that has already been finished.");

  if (m_bitfield.size_set() >= m_bitfield.size_bits())
    throw internal_error("FileList::mark_completed(...) m_bitfield.size_set() >= m_bitfield.size_bits().");

  if (index >= size_chunks() || completed_chunks() >= size_chunks())
    throw internal_error("FileList::mark_completed(...) received an invalid index.");

  m_bitfield.set(index);
  inc_completed(begin(), index);
}

FileList::iterator
FileList::inc_completed(iterator firstItr, uint32_t index) {
  firstItr         = std::find_if(firstItr, end(), rak::less(index, std::mem_fun(&File::range_second)));
  iterator lastItr = std::find_if(firstItr, end(), rak::less(index + 1, std::mem_fun(&File::range_second)));

  if (firstItr == end())
    throw internal_error("FileList::inc_completed() first == m_entryList->end().");

  std::for_each(firstItr,
                lastItr == end() ? end() : (lastItr + 1),
                std::mem_fun(&File::inc_completed_protected));

  return lastItr;
}

void
FileList::update_completed() {
  if (!m_bitfield.is_tail_cleared())
    throw internal_error("Content::update_done() called but m_bitfield's tail isn't cleared.");

  if (m_bitfield.is_all_set()) {
    for (iterator itr = begin(), last = end(); itr != last; ++itr)
      (*itr)->set_completed_protected((*itr)->size_chunks());

  } else {
    // Clear any old progress data from the entries as we don't clear
    // this on close, etc.
    for (iterator itr = begin(), last = end(); itr != last; ++itr)
      (*itr)->set_completed_protected(0);

    if (m_bitfield.is_all_unset())
      return;

    iterator entryItr = begin();

    for (Bitfield::size_type index = 0; index < m_bitfield.size_bits(); ++index)
      if (m_bitfield.get(index))
        entryItr = inc_completed(entryItr, index);
  }
}

}
