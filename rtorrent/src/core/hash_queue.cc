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

#include "config.h"

#include <algorithm>
#include <stdexcept>
#include <sigc++/bind.h>

#include "download.h"
#include "download_list.h"
#include "rak/functional.h"
#include "hash_queue.h"

namespace core {

bool
HashQueue::is_queued(Download* download) const {
  return
    download->download()->is_hash_checking() ||
    std::find_if(begin(), end(), rak::equal(download, std::mem_fun(&HashQueueNode::download))) != end();
}

void
HashQueue::insert(Download* download) {
  if (download->download()->is_hash_checking() || find(download) != end())
    return;

  if (download->download()->is_hash_checked()) {
    m_downloadList->hash_done(download);
    return;
  }

  if (find(download) != end())
    throw torrent::internal_error("HashQueue::insert(...) download already in queue.");

  iterator itr = Base::insert(end(), new HashQueueNode(download));

  (*itr)->set_connection(download->download()->signal_hash_done(sigc::bind(sigc::mem_fun(*this, &HashQueue::receive_hash_done), download)));

  fill_queue();
}

void
HashQueue::remove(Download* d) {
  iterator itr = find(d);

  if (itr == end())
    return;

  // We don't do anything if we're already checking, just disconnect.
//   if ((*itr)->download()->download()->is_hash_checking()) {
//     // What do we do if we're already checking?
//   }

  delete *itr;
  Base::erase(itr);

  fill_queue();
}

HashQueue::iterator
HashQueue::find(Download* d) {
  return std::find_if(begin(), end(), rak::equal(d, std::mem_fun(&HashQueueNode::download)));
}

void
HashQueue::receive_hash_done(Download* d) {
  iterator itr = find(d);

  if (itr == end())
    return;

  delete *itr;
  Base::erase(itr);

  m_downloadList->hash_done(d);
  fill_queue();
}

void
HashQueue::fill_queue() {
  if (empty() || front()->download()->download()->is_hash_checking())
    return;

  if (front()->download()->download()->is_hash_checked())
    throw std::logic_error("core::HashQueue::fill_queue() encountered a checked hash");
  
  front()->download()->download()->hash_check();
}

}
