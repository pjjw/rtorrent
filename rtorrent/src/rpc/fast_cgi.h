// rTorrent - BitTorrent client
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

#ifndef RTORRENT_RPC_FAST_CGI_H
#define RTORRENT_RPC_FAST_CGI_H

#include <string>
#include <torrent/event.h>

struct FCGX_Request;

namespace rak {
  template <typename Result, typename Arg1, typename Arg2> class function2;
  template <typename Result, typename Arg1, typename Arg2, typename Arg3> class function3;
}

namespace rpc {

class FastCgi : public torrent::Event {
public:
  typedef rak::function2<bool, const char*, uint32_t>             slot_write;
  typedef rak::function3<bool, const char*, uint32_t, slot_write> slot_process;

  FastCgi(const std::string& path);
  virtual ~FastCgi();

  const std::string   path() const { return m_path; }

  void                set_slot_process(slot_process::base_type* s) { m_slotProcess.set(s); }

  virtual void        event_read();
  virtual void        event_write();
  virtual void        event_error();

  bool                receive_write(const char* buffer, uint32_t length);

private:
  static bool         m_initialized;

  FCGX_Request*       m_request;
  std::string         m_path;

  slot_process        m_slotProcess;
};

}

#endif
