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

#ifndef LIBTORRENT_PEER_H
#define LIBTORRENT_PEER_H

#include <string>
#include <inttypes.h>

namespace torrent {

class PeerConnectionBase;
class Rate;

// == and = operators works as expected.

// The Peer class is a wrapper around the internal peer class. This
// peer class may be invalidated during a torrent::work call. So if
// you keep a list or single instances in the client, you need to
// listen to the appropriate signals from the download to keep up to
// date. 
class Peer {
public:
  Peer()                      : m_ptr(NULL) {}
  Peer(PeerConnectionBase* p) : m_ptr(p) {}

  // Does not check if it has been removed from the download.
  bool                 is_valid() const { return m_ptr; }
  bool                 is_incoming() const;

  bool                 is_local_choked();
  bool                 is_local_interested();
  bool                 is_remote_choked();
  bool                 is_remote_interested();

  bool                 is_snubbed();
  void                 set_snubbed(bool v);

  std::string          id();
  std::string          address();
  uint16_t             port();
  const char*          options();

  const Rate*          down_rate();
  const Rate*          up_rate();
  const Rate*          peer_rate();

  uint32_t             incoming_queue_size();
  uint32_t             outgoing_queue_size();

  // index == -1 for incoming pieces that we don't want anymore.
  uint32_t             incoming_index(uint32_t pos);
  uint32_t             incoming_offset(uint32_t pos);
  uint32_t             incoming_length(uint32_t pos);

  const unsigned char* bitfield_data();
  uint32_t             bitfield_size();

  uint32_t             chunks_done();

  PeerConnectionBase*  ptr()                            { return m_ptr; }
  void                 set_ptr(PeerConnectionBase* ptr) { m_ptr = ptr; }

  bool                 operator == (const Peer& p)      { return m_ptr == p.m_ptr; }

private:
  PeerConnectionBase*  m_ptr;
};

}

#endif
