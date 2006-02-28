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

#ifndef LIBTORRENT_NET_SOCKET_MANAGER_H
#define LIBTORRENT_NET_SOCKET_MANAGER_H

#include <inttypes.h>
#include <rak/socket_address.h>

#include "socket_fd.h"

namespace torrent {

// Socket manager keeps tabs on how many open sockets we got and helps
// with opening addresses. It will also make sure ip address filtering
// gets handled.
//
// It closes the opened/received socket if the connection is unwanted.
//
// TODO: Rename received to receive.

class SocketManager {
public:
  SocketManager();
  
  // Check that we have not surpassed the max number of open sockets
  // and that we're allowed to connect to the socket address.
  bool                can_connect(const rak::socket_address& sa);

  // Call this to keep the socket count up to date.
  void                increment_sockets();
  void                decrement_sockets();

  //
  // Old interface.
  //
  SocketFd            open(const rak::socket_address& sa);
  SocketFd            received(SocketFd fd, const rak::socket_address& sa);

  void                local(__UNUSED SocketFd fd)   { m_size++; }

  void                close(SocketFd fd);
  //
  //
  //

  uint32_t            size() const                  { return m_size; }

  uint32_t            max_size() const              { return m_max; }
  void                set_max_size(uint32_t s)      { m_max = s; }

  // Propably going to have to make m_bindAddress a pointer to make it
  // safe.
  rak::socket_address* bind_address()               { return &m_bindAddress; }

private:
  uint32_t            m_size;
  uint32_t            m_max;

  rak::socket_address m_bindAddress;
};

// Move somewhere else.
struct SocketAddressCompact {
  SocketAddressCompact() {}
  SocketAddressCompact(uint32_t a, uint16_t p) : addr(a), port(p) {}

  operator rak::socket_address () const {
    rak::socket_address sa;
    sa.sa_inet()->clear();
    sa.sa_inet()->set_port_n(port);
    sa.sa_inet()->set_address_n(addr);

    return sa;
  }

  uint32_t addr;
  uint16_t port;

  const char*         c_str() const { return reinterpret_cast<const char*>(this); }
} __attribute__ ((packed));

}

#endif

