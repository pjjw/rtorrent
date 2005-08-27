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

#ifndef RTORRENT_CORE_DOWNLOAD_H
#define RTORRENT_CORE_DOWNLOAD_H

#include <sigc++/connection.h>
#include <torrent/download.h>
#include <torrent/torrent.h>

namespace core {

class Download {
public:
  Download();
  ~Download() { release_download(); }

  bool               is_open()                       { return m_download.is_open(); }
  inline bool        is_done();

  void               start();

  void               set_download(torrent::Download d);
  void               release_download();

  torrent::Download& get_download()                  { return m_download; }
  const torrent::Download& get_download() const      { return m_download; }
  std::string        get_hash()                      { return m_download.get_hash(); }
  torrent::Bencode&  get_bencode()                   { return m_download.get_bencode(); }
  
  const std::string& get_message()                   { return m_message; }

  void               set_root_directory(const std::string& d);

  void               set_connection_leech(const std::string& name) { m_connectionLeech = name; }
  void               set_connection_seed(const std::string& name)  { m_connectionSeed = name; }

  void               enable_udp_trackers(bool state);

  // Helper functions for calling functions in torrent::Download
  // through sigc++.
  template <typename Ret, Ret (torrent::Download::*func)()>
  void               call()                                                { (m_download.*func)(); }

  template <typename Ret, typename Arg1, Ret (torrent::Download::*func)(Arg1)>
  void               call(Arg1 a1)                                         { (m_download.*func)(a1); }

  bool operator == (const std::string& str)                                { return str == m_download.get_hash(); }

  void               receive_finished();

private:
  void               receive_tracker_msg(std::string msg);
  void               receive_storage_error(std::string msg);

  static torrent::Download::ConnectionType string_to_connection_type(const std::string& name);

  torrent::Download  m_download;

  std::string        m_message;

  std::string        m_connectionLeech;
  std::string        m_connectionSeed;

  sigc::connection   m_connTrackerSucceded;
  sigc::connection   m_connTrackerFailed;
  sigc::connection   m_connStorageError;
};

inline bool
Download::is_done() {
  return m_download.get_chunks_done() == m_download.get_chunks_total();
}

}

#endif
