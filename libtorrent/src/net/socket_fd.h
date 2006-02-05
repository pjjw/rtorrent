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

#ifndef LIBTORRENT_NET_SOCKET_FD_H
#define LIBTORRENT_NET_SOCKET_FD_H

#include <unistd.h>

namespace torrent {

class SocketAddress;

class SocketFd {
public:
  SocketFd() : m_fd(-1) {}
  explicit SocketFd(int fd) : m_fd(fd) {}

  bool                is_valid() const                        { return m_fd >= 0; }
  
  int                 get_fd() const                          { return m_fd; }
  void                set_fd(int fd)                          { m_fd = fd; }

  bool                set_nonblock();
  bool                set_throughput();
  bool                set_reuse_address(bool state);

  int                 get_error() const;

  bool                open_stream();
  bool                open_datagram();
  void                close();

  void                clear()                                 { m_fd = -1; }

  bool                bind(const SocketAddress& sa);
  bool                connect(const SocketAddress& sa);

  bool                listen(int size);
  SocketFd            accept(SocketAddress* sa);

//   unsigned int        get_read_queue_size() const;
//   unsigned int        get_write_queue_size() const;

private:
  int                 m_fd;
};

}

#endif