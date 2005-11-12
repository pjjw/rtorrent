// rTorrent - BitTorrent client
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

#include <cstring>
#include <stdexcept>
#include <unistd.h>
#include <sys/time.h>
#include <torrent/poll_epoll.h>
#include <torrent/torrent.h>

#include "poll_manager_epoll.h"

namespace core {

PollManagerEPoll*
PollManagerEPoll::create(int maxOpenSockets) {
  torrent::PollEPoll* p = torrent::PollEPoll::create(maxOpenSockets);

  if (p == NULL)
    return NULL;
  else
    return new PollManagerEPoll(p);
}

PollManagerEPoll::~PollManagerEPoll() {
}

void
PollManagerEPoll::poll(utils::Timer timeout) {
  // Add 1ms to ensure we don't idle loop due to the lack of
  // resolution.
  torrent::perform();
  timeout = std::min(timeout, utils::Timer(torrent::next_timeout()));

  if (m_httpStack.is_busy()) {
    // When we're using libcurl we need to use select, but as this is
    // inefficient we try avoiding it whenever possible.
#if defined USE_VARIABLE_FDSET
    std::memset(m_readSet, 0, m_setSize);
    std::memset(m_writeSet, 0, m_setSize);
    std::memset(m_errorSet, 0, m_setSize);
#else
    FD_ZERO(m_readSet);
    FD_ZERO(m_writeSet);
    FD_ZERO(m_errorSet);
#endif    
    FD_SET(static_cast<torrent::PollEPoll*>(m_poll)->file_descriptor(), m_readSet);

    unsigned int maxFd = std::max((unsigned int)static_cast<torrent::PollEPoll*>(m_poll)->file_descriptor(),
				  m_httpStack.fdset(m_readSet, m_writeSet, m_errorSet));

    timeval t = timeout.tval();

    if (select(maxFd + 1, m_readSet, m_writeSet, m_errorSet, &t) == -1)
      return check_error();

    m_httpStack.perform();

    if (!FD_ISSET(static_cast<torrent::PollEPoll*>(m_poll)->file_descriptor(), m_readSet)) {
      // Need to call perform here so that scheduled task get done
      // even if there's no socket events outside of the http stuff.
      torrent::perform();
      return;
    }

    // Clear the timeout since we've already used it in the select call.
    timeout = utils::Timer();
  }

  // Yes, below is how much code really *should* have been in this
  // function. ;)

  if (static_cast<torrent::PollEPoll*>(m_poll)->poll((timeout.usec() + 999) / 1000) == -1)
    return check_error();

  torrent::perform();
  static_cast<torrent::PollEPoll*>(m_poll)->perform();
}

}
