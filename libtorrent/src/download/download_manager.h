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
// Contact:  Jari Sundell <jaris@ifi.uio.no>
//
//           Skomakerveien 33
//           3185 Skoppum, NORWAY

#ifndef LIBTORRENT_DOWNLOAD_MANAGER_H
#define LIBTORRENT_DOWNLOAD_MANAGER_H

#include <list>

namespace torrent {

class DownloadWrapper;

class DownloadManager {
public:
  typedef std::list<DownloadWrapper*>  DownloadList;
  typedef DownloadList::iterator       iterator;
  typedef DownloadList::const_iterator const_iterator;

  ~DownloadManager() { clear(); }

  void                add(DownloadWrapper* d);
  void                remove(const std::string& hash);

  void                clear();

  DownloadWrapper*    find(const std::string& hash);

  DownloadList&       get_list() { return m_downloads; }

private:
  DownloadList        m_downloads;
};

}

#endif
