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

#include <cerrno>
#include <cstring>
#include <iostream>

#include <unistd.h>
#include <torrent/exceptions.h>
#include <torrent/event.h>

#include "poll_ports.h"

#ifdef USE_PORTS
/*
 * We should use <poll.h> here, but it seems to conflict with the
 * <torrent/poll.h> header, so use <sys/poll.h> instead.  Since all
 * poll.h does is include sys/poll.h, this shouldn't cause any
 * problems.
 */
# include <sys/poll.h>
# include <port.h>
#endif

namespace torrent {

#ifdef USE_PORTS
inline Event*
PollPorts::event_object(Event* e) {
  return m_table[e->file_descriptor()].first;
}

inline int
PollPorts::event_mask(Event* e) {
  if (event_object(e) != e)
    return 0;
  return m_table[e->file_descriptor()].second;
}

inline void
PollPorts::set_event_object(Event* e) {
  m_table[e->file_descriptor()] = std::pair<Event*,int>(e, 0);
}

inline void
PollPorts::set_event_mask(Event* e, int m) {
  m_table[e->file_descriptor()].second = m;
}

inline void
PollPorts::modify(Event* event, int mask) {
  if (event_object(event) != event)
    return;

  if (event_mask(event) == mask)
    return;

  set_event_mask(event, mask);

  if (mask == 0) {
    port_dissociate(m_fd, PORT_SOURCE_FD, event->file_descriptor());
    return;
  }

  if (port_associate(m_fd, PORT_SOURCE_FD, event->file_descriptor(),
		  mask, event) == -1)
	  throw internal_error("PollPorts::modify(...) port_associate failed");
}

PollPorts*
PollPorts::create(int maxOpenSockets) {
  int fd = port_create();

  if (fd == -1)
    return NULL;

  return new PollPorts(fd, 1024, maxOpenSockets);
}

PollPorts::PollPorts(int fd, int maxEvents, int maxOpenSockets) :
  m_fd(fd),
  m_maxEvents(maxEvents),
  m_waitingEvents(0),
  m_events(new port_event_t[maxEvents]) {
  m_table.resize(maxOpenSockets);
}

PollPorts::~PollPorts() {
  m_table.clear();
  delete [] m_events;

  ::close(m_fd);
}

int
PollPorts::poll(int msec) {
  timespec_t timeout;
  timeout.tv_sec = msec / 1000;
  timeout.tv_nsec = (msec * 1000000L) % 1000000000L;

  uint_t nfds = 1;

  int ret = port_getn(m_fd, m_events, m_maxEvents, &nfds, &timeout);

  if (ret == -1 && errno != ETIME) {
	  std::cerr << "error from ports, maxevents="<<m_maxEvents<<", nfds="<<nfds<<" msec="<<msec<<"\n";
    return -1;
  }

  return m_waitingEvents = nfds;
}

// We check m_table to make sure the Event is still listening to the
// event, so it is safe to remove Event's while in working.
//
// TODO: Do we want to guarantee if the Event has been removed from
// some event but not closed, it won't call that event? Think so...
void
PollPorts::perform() {
  for (port_event_t *itr = m_events, *last = m_events + m_waitingEvents; itr != last; ++itr) {

    // Each branch must check for data.ptr != NULL to allow the socket
    // to remove itself between the calls.
    //
    // TODO: Make it so that it checks that read/write is wanted, that
    // it wasn't removed from one of them but not closed.

    Event *e = static_cast<Event*>(itr->portev_user);
    if (e == NULL)
      continue;

    if (itr->portev_events & POLLERR 
        && event_mask(e) & POLLERR)
      e->event_error();

    if (itr->portev_user != e)
      continue;

    if (itr->portev_events & POLLIN
        && event_mask(e) & POLLIN)
      e->event_read();

    if (itr->portev_user != e)
      continue;

    if (itr->portev_events & POLLOUT
        && event_mask(e) & POLLOUT)
      e->event_write();

    if (itr->portev_user != e)
      continue;

    // Since port events are one-shot, re-add the fd after we process
    // its events.

    port_associate(m_fd, PORT_SOURCE_FD, itr->portev_object,
        event_mask(e), e);
  }

  m_waitingEvents = 0;
}

void
PollPorts::open(Event* event) {
  if (event_object(event) == event && event_mask(event) != 0)
    throw internal_error("PollPorts::open(...) called but the file descriptor is active");
  set_event_object(event);
}

void
PollPorts::close(Event* event) {
  if (event_mask(event) != 0)
    throw internal_error("PollPorts::close(...) called but the file descriptor is active");

  for (port_event_t *itr = m_events, *last = m_events + m_waitingEvents; itr != last; ++itr)
    if (itr->portev_user == event)
      itr->portev_user = NULL;
}

bool
PollPorts::in_read(Event* event) {
  return event_mask(event) & POLLIN;
}

bool
PollPorts::in_write(Event* event) {
  return event_mask(event) & POLLOUT;
}

bool
PollPorts::in_error(Event* event) {
  return event_mask(event) & POLLERR;
}

void
PollPorts::insert_read(Event* event) {
  modify(event, event_mask(event) | POLLIN);
}

void
PollPorts::insert_write(Event* event) {
  modify(event, event_mask(event) | POLLOUT);
}

void
PollPorts::insert_error(Event* event) {
  modify(event, event_mask(event) | POLLERR);
}

void
PollPorts::remove_read(Event* event) {
  modify(event, event_mask(event) & ~POLLIN);
}

void
PollPorts::remove_write(Event* event) {
  modify(event, event_mask(event) & ~POLLOUT);
}

void
PollPorts::remove_error(Event* event) {
  modify(event, event_mask(event) & ~POLLERR);
}

#else // USE_PORTS

PollPorts*
PollPorts::create(int maxOpenSockets) {
  return NULL;
}

PollPorts::~PollPorts() {
}

int
PollPorts::poll(int msec) {
  throw internal_error("An PollPorts function was called, but it is disabled.");
}

void
PollPorts::perform() {
  throw internal_error("An PollPorts function was called, but it is disabled.");
}

uint32_t
PollPorts::open_max() const {
  throw internal_error("An PollPorts function was called, but it is disabled.");
}

void
PollPorts::open(torrent::Event* event) {
}

void
PollPorts::close(torrent::Event* event) {
}

bool
PollPorts::in_read(torrent::Event* event) {
  throw internal_error("An PollPorts function was called, but it is disabled.");
}

bool
PollPorts::in_write(torrent::Event* event) {
  throw internal_error("An PollPorts function was called, but it is disabled.");
}

bool
PollPorts::in_error(torrent::Event* event) {
  throw internal_error("An PollPorts function was called, but it is disabled.");
}

void
PollPorts::insert_read(torrent::Event* event) {
}

void
PollPorts::insert_write(torrent::Event* event) {
}

void
PollPorts::insert_error(torrent::Event* event) {
}

void
PollPorts::remove_read(torrent::Event* event) {
}

void
PollPorts::remove_write(torrent::Event* event) {
}

void
PollPorts::remove_error(torrent::Event* event) {
}

PollPorts::PollPorts(int fd, int maxEvents, int maxOpenSockets) {
  throw internal_error("An PollPorts function was called, but it is disabled.");
}

#endif // USE_PORTS

}
