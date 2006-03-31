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

#ifndef RTORRENT_CORE_DOWNLOAD_H
#define RTORRENT_CORE_DOWNLOAD_H

#include <sigc++/connection.h>
#include <torrent/download.h>
#include <torrent/file_list.h>
#include <torrent/tracker_list.h>
#include <torrent/torrent.h>

#include "utils/variable_map.h"

namespace core {

class Download {
public:
  typedef torrent::Download             download_type;
  typedef torrent::FileList             file_list_type;
  typedef torrent::TrackerList          tracker_list_type;
  typedef download_type::ConnectionType connection_type;
  typedef utils::VariableMap            variable_map_type;

  Download(download_type d);
  ~Download();

  bool                is_open() const                          { return m_download.is_open(); }
  inline bool         is_done() const                          { return m_download.chunks_done() == m_download.chunks_total(); }

  void                start();
  void                stop();

  // Add functions like pause/etc.

  variable_map_type*  variable()                               { return &m_variables; }
  std::string         variable_string(const std::string& key)  { return m_variables.get_string(key); }

  download_type*       download()                              { return &m_download; }
  const download_type* download() const                        { return &m_download; }

  torrent::Object*    bencode()                                { return m_download.bencode(); }
  file_list_type*     file_list()                              { return &m_fileList; }
  tracker_list_type*  tracker_list()                           { return &m_trackerList; }

  const std::string&  info_hash() const                        { return m_download.info_hash(); }
  const std::string&  message() const                          { return m_message; }

  uint32_t            chunks_failed() const                    { return m_chunksFailed; }

  void                enable_udp_trackers(bool state);

  uint32_t            priority();
  void                set_priority(uint32_t p);

  // Helper functions for calling functions in download_type
  // through sigc++.
  template <typename Ret, Ret (download_type::*func)()>
  void                call()                                                { (m_download.*func)(); }

  template <typename Ret, typename Arg1, Ret (download_type::*func)(Arg1)>
  void                call(Arg1 a1)                                         { (m_download.*func)(a1); }

  bool operator == (const std::string& str)                                { return str == m_download.info_hash(); }

  void                receive_finished();

  static connection_type string_to_connection_type(const std::string& name);
  static const char*     connection_type_to_string(connection_type t);

  static uint32_t     string_to_priority(const std::string& name);
  static const char*  priority_to_string(uint32_t p);

  float               distributed_copies() const;

private:
  Download(const Download&);
  void operator () (const Download&);

  void                receive_tracker_msg(std::string msg);
  void                receive_storage_error(std::string msg);

  void                receive_chunk_failed(uint32_t idx);

  const char*         connection_current() const                    { return connection_type_to_string(m_download.connection_type()); }
  void                set_connection_current(const std::string& t)  { return m_download.set_connection_type(string_to_connection_type(t.c_str())); }

  void                set_root_directory(const std::string& path);

  // Store the FileList instance so we can use slots etc on it.
  download_type       m_download;
  file_list_type      m_fileList;
  tracker_list_type   m_trackerList;

  std::string         m_message;
  uint32_t            m_chunksFailed;

  variable_map_type   m_variables;

  sigc::connection    m_connTrackerSucceded;
  sigc::connection    m_connTrackerFailed;
  sigc::connection    m_connStorageError;
};

}

#endif
