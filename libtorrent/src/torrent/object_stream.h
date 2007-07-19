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

#ifndef LIBTORRENT_OBJECT_STREAM_H
#define LIBTORRENT_OBJECT_STREAM_H

#include <ios>
#include <string>
#include <torrent/common.h>

namespace torrent {

std::string object_sha1(const Object* object) LIBTORRENT_EXPORT;

// Assumes the stream's locale has been set to POSIX or C.  Max depth
// is 1024, this ensures files consisting of only 'l' don't segfault
// the client.
void object_read_bencode(std::istream* input, Object* object, uint32_t depth = 0) LIBTORRENT_EXPORT;

// Assumes the stream's locale has been set to POSIX or C.
void object_write_bencode(std::ostream* output, const Object* object) LIBTORRENT_EXPORT;

std::istream& operator >> (std::istream& input, Object& object) LIBTORRENT_EXPORT;
std::ostream& operator << (std::ostream& output, const Object& object) LIBTORRENT_EXPORT;

// object_buffer_t contains the start and end of the buffer.
typedef std::pair<char*, char*> object_buffer_t;
typedef object_buffer_t (*object_write_t)(void* data, object_buffer_t buffer);

object_buffer_t object_write_bencode_c(object_write_t writeFunc, void* data, object_buffer_t buffer, const Object* object) LIBTORRENT_EXPORT;

// To char buffer. 'data' is NULL.
object_buffer_t object_write_to_buffer(void* data, object_buffer_t buffer) LIBTORRENT_EXPORT;
object_buffer_t object_write_to_sha1(void* data, object_buffer_t buffer) LIBTORRENT_EXPORT;
object_buffer_t object_write_to_stream(void* data, object_buffer_t buffer) LIBTORRENT_EXPORT;
}

#endif
