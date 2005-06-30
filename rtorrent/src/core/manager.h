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
// Contact:  Jari Sundell <jaris@ifi.uio.no>
//
//           Skomakerveien 33
//           3185 Skoppum, NORWAY

#ifndef RTORRENT_CORE_MANAGER_H
#define RTORRENT_CORE_MANAGER_H

#include <iosfwd>

#include "download_list.h"
#include "download_store.h"
#include "hash_queue.h"
#include "http_queue.h"
#include "poll.h"
#include "log.h"

namespace torrent {
  class Bencode;
}

namespace core {

class Manager {
public:
  typedef DownloadList::iterator                    DListItr;
  typedef sigc::slot1<void, DownloadList::iterator> SlotReady;
  typedef sigc::slot0<void>                         SlotFailed;

  Manager() : m_portRandom(false), m_portFirst(6890), m_portLast(6999) {}

  DownloadList&       get_download_list()                 { return m_downloadList; }
  DownloadStore&      get_download_store()                { return m_downloadStore; }
  HashQueue&          get_hash_queue()                    { return m_hashQueue; }
  HttpQueue&          get_http_queue()                    { return m_httpQueue; }

  Poll&               get_poll()                          { return m_poll; }
  Log&                get_log_important()                 { return m_logImportant; }
  Log&                get_log_complete()                  { return m_logComplete; }

  void                set_port_random(bool v)             { m_portRandom = v; }
  void                set_port_range(int a, int b)        { m_portFirst = a; m_portLast = b; }

  void                initialize();
  void                cleanup();

  void                shutdown(bool force);

  void                insert(std::string uri);
  DListItr            erase(DListItr itr);

  void                start(Download* d);
  void                stop(Download* d);

  void                check_hash(Download* d);

  void                receive_download_done(Download* d, bool check_hash);

private:
  void                listen_open();

  void                create_http(const std::string& uri);
  void                create_final(std::istream* s);

  void                initialize_bencode(Download* d);

  void                prepare_hash_check(Download* d);

  void                receive_http_failed(std::string msg);
  void                receive_download_done_hash_checked(Download* d);
  void                receive_download_inserted(Download* d);

  DownloadList        m_downloadList;
  DownloadStore       m_downloadStore;
  HashQueue           m_hashQueue;
  HttpQueue           m_httpQueue;

  Poll                m_poll;
  Log                 m_logImportant;
  Log                 m_logComplete;

  bool                m_portRandom;
  int                 m_portFirst;
  int                 m_portLast;
};

}

#endif
