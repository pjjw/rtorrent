// libTorrent - BitTorrent library
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

#ifndef LIBTORRENT_PROTOCOL_PEER_CONNECTION_BASE_H
#define LIBTORRENT_PROTOCOL_PEER_CONNECTION_BASE_H

#include "data/chunk.h"
#include "data/chunk_handle.h"
#include "net/socket_stream.h"
#include "globals.h"
#include "torrent/connection_manager.h"
#include "torrent/poll.h"

#include "peer_info.h"
#include "peer_chunks.h"
#include "protocol_base.h"
#include "request_list.h"

#include "manager.h"

namespace torrent {

// Base class for peer connection classes. Rename to PeerConnection
// when the migration is complete?
//
// This should really be modularized abit, there's too much stuff in
// PeerConnectionBase and its children. Do we use additional layers of
// inheritance or member instances?

class DownloadMain;

class PeerConnectionBase : public SocketStream {
public:
  typedef ProtocolBase           ProtocolRead;
  typedef ProtocolBase           ProtocolWrite;

  // Find an optimal number for this.
  static const uint32_t read_size = 64;

  PeerConnectionBase();
  virtual ~PeerConnectionBase();
  
  void                initialize(DownloadMain* download, PeerInfo* p, SocketFd fd, Bitfield* bitfield);

  bool                is_up_choked()                { return m_up->choked(); }
  bool                is_up_interested()            { return m_up->interested(); }
  bool                is_down_choked()              { return m_down->choked(); }
  bool                is_down_interested()          { return m_down->interested(); }

  bool                is_upload_wanted() const      { return m_down->interested() && !m_peerChunks.is_snubbed(); }

  bool                is_seeder() const             { return m_peerChunks.is_seeder(); }

  const PeerInfo*     peer_info() const             { return m_peerInfo; }
  PeerChunks*         peer_chunks()                 { return &m_peerChunks; }

  RequestList*        download_queue()              { return &m_downloadQueue; }

  // Make sure you choke the peer when snubbing. Snubbing a peer will
  // only cause it not to be unchoked.
  //
  // Move this stuff to PeerChunks.
  void                set_snubbed(bool v);

  rak::timer          time_last_choked() const      { return m_timeLastChoked; }

  // These must be implemented by the child class.
  virtual void        initialize_custom() = 0;

  virtual void        update_interested() = 0;

  virtual void        receive_finished_chunk(int32_t i) = 0;
  virtual bool        receive_keepalive() = 0;
  void                receive_choke(bool v);

  virtual void        event_error();

  void                push_unread(const void* data, uint32_t size);

protected:
  typedef Chunk::iterator ChunkPart;

  inline bool         read_remaining();
  inline bool         write_remaining();

  void                load_down_chunk(const Piece& p);
  void                load_up_chunk();

  void                receive_throttle_down_activate();
  void                receive_throttle_up_activate();

  void                read_request_piece(const Piece& p);
  void                read_cancel_piece(const Piece& p);

  void                read_buffer_move_unused();

  void                write_prepare_piece();

  bool                down_chunk();
  bool                down_chunk_from_buffer();
  bool                down_chunk_skip();

  bool                up_chunk();

  void                down_chunk_release();
  void                up_chunk_release();

  bool                should_request();
  bool                try_request_pieces();

  void                set_remote_interested();
  void                set_remote_not_interested();

  // Insert into the poll unless we're blocking for throttling etc.
  void                read_insert_poll_safe();
  void                write_insert_poll_safe();

  DownloadMain*       m_download;

  ProtocolRead*       m_down;
  ProtocolWrite*      m_up;

  PeerInfo*           m_peerInfo;
  PeerChunks          m_peerChunks;

  Piece               m_downPiece;
  ChunkHandle         m_downChunk;

  uint32_t            m_downStall;

  Piece               m_upPiece;
  ChunkHandle         m_upChunk;

  bool                m_sendChoked;
  bool                m_sendInterested;

  RequestList         m_downloadQueue;

  rak::timer          m_timeLastChoked;
  rak::timer          m_timeLastRead;
};

inline void
PeerConnectionBase::push_unread(const void* data, uint32_t size) {
  std::memcpy(m_down->buffer()->end(), data, size);
  m_down->buffer()->move_end(size);
}

inline bool
PeerConnectionBase::read_remaining() {
  m_down->buffer()->move_position(read_stream_throws(m_down->buffer()->position(), m_down->buffer()->remaining()));

  return !m_down->buffer()->remaining();
}

inline bool
PeerConnectionBase::write_remaining() {
  m_up->buffer()->move_position(write_stream_throws(m_up->buffer()->position(), m_up->buffer()->remaining()));

  return !m_up->buffer()->remaining();
}

inline void
PeerConnectionBase::read_insert_poll_safe() {
  if (m_down->get_state() != ProtocolRead::IDLE)
    return;

  manager->poll()->insert_read(this);
}

inline void
PeerConnectionBase::write_insert_poll_safe() {
  if (m_up->get_state() != ProtocolWrite::IDLE)
    return;

  manager->poll()->insert_write(this);
}

}

#endif
