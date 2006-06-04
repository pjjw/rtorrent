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

#include "config.h"

#include <algorithm>
#include <functional>
#include <rak/functional.h>

#include "block.h"
#include "block_transfer.h"
#include "exceptions.h"

namespace torrent {

inline void
Block::invalidate_transfer(BlockTransfer* transfer) {
  // FIXME: Various other accounting like position and counters.
  if (transfer->is_erased()) {
    delete transfer;

  } else {
    m_notStalled -= transfer->stall() == 0;

    transfer->set_block(NULL);
  }
}

void
Block::clear() {
  std::for_each(m_queued.begin(), m_queued.end(), std::bind1st(std::mem_fun(&Block::invalidate_transfer), this));
  std::for_each(m_transfers.begin(), m_transfers.end(), std::bind1st(std::mem_fun(&Block::invalidate_transfer), this));

  m_queued.clear();
  m_transfers.clear();

  m_finished = false;

  if (m_notStalled != 0)
    throw internal_error("Block::clear() m_stalled != 0.");
}

BlockTransfer*
Block::insert(PeerInfo* peerInfo) {
  if (find_queued(peerInfo) || find_queued(peerInfo))
    throw internal_error("Block::insert(...) find_queued(peerInfo) || find_queued(peerInfo).");

  m_notStalled++;

  transfer_list::iterator itr = m_queued.insert(m_queued.end(), new BlockTransfer());

  (*itr)->set_peer_info(peerInfo);
  (*itr)->set_block(this);
  (*itr)->set_position(BlockTransfer::position_invalid);
  (*itr)->set_stall(0);

  return (*itr);
}
  
void
Block::erase(BlockTransfer* transfer) {
  // Check if the transfer was orphaned, if so just delete it.
  if (transfer->block() == NULL) {
    delete transfer;
    return;
  }

  if (transfer->is_erased())
    throw internal_error("Block::erase(...) transfer already erased.");

  Block* block = transfer->block();

  block->m_notStalled -= transfer->stall() == 0;

  if (transfer->is_queued()) {
    transfer_list::iterator itr = std::find(block->m_queued.begin(), block->m_queued.end(), transfer);

    if (itr == block->m_queued.end())
      throw internal_error("Block::erase(...) Could not find transfer.");

    delete *itr;
    block->m_queued.erase(itr);

  } else {
    transfer_list::iterator itr = std::find(block->m_transfers.begin(), block->m_transfers.end(), transfer);

    if (itr == block->m_transfers.end())
      throw internal_error("Block::erase(...) Could not find transfer.");

//     // Need to do something different here for now, i think.
    delete *itr;
    block->m_transfers.erase(itr);

//     transfer->set_stall(BlockTransfer::stall_erased);
  }
}

void
Block::transfering(BlockTransfer* transfer) {
  if (transfer->block() == NULL)
    throw internal_error("Block::transfering(...) transfer->block() == NULL.");

  Block* block = transfer->block();

  transfer_list::iterator itr = std::find(block->m_queued.begin(), block->m_queued.end(), transfer);

  if (itr == block->m_queued.end())
    throw internal_error("Block::transfering(...) not queued.");

  transfer->set_position(0);

  block->m_queued.erase(itr);
  block->m_transfers.insert(block->m_transfers.end(), transfer);
}

void
Block::stalled(BlockTransfer* transfer) {
  if (!transfer->is_valid())
    return;

  if (transfer->stall() == 0) {
    if (transfer->block()->m_notStalled == 0)
      throw internal_error("Block::stalled(...) m_notStalled == 0.");

    transfer->block()->m_notStalled--;

    // Do magic here.
  }

  transfer->set_stall(transfer->stall() + 1);
}

void
Block::completed(BlockTransfer* transfer) {
  if (transfer->block() == NULL)
    throw internal_error("Block::completed(...) transfer->block() == NULL.");

  if (transfer->is_erased())
    throw internal_error("Block::completed(...) transfer is erased.");

  if (transfer->is_queued())
    throw internal_error("Block::completed(...) transfer is queued.");

  Block* block = transfer->block();

  block->m_finished = true;
  block->m_notStalled -= transfer->stall() == 0;

  transfer->set_stall(BlockTransfer::stall_erased);

  // Currently just throw out the queued transfers. In case the hash
  // check fails, we might consider telling pcb during the call to
  // Block::transfering(...). But that would propably not be correct
  // as we want to trigger cancel messages from here, as hash fail is
  // a rare occurrence.
  std::for_each(block->m_queued.begin(), block->m_queued.end(), std::bind1st(std::mem_fun(&Block::invalidate_transfer), block));
  block->m_queued.clear();

  // We need to invalidate those unfinished and keep the one that
  // finished for later reference.

  // Do a stable partition, accure the transfers that have completed
  // at the start. Use a 'try' counter that also adjust the sizes.

  // Temporary hack.
//   for (transfer_list::iterator itr = block->m_transfers.begin(), last = block->m_transfers.end(); itr != last; ) {
//     if ((*itr)->is_erased()) {
//       itr++;
//     } else {
//       itr = block->m_transfers.erase(itr);
//     }
//   }

  std::for_each(block->m_transfers.begin(), block->m_transfers.end(), std::bind1st(std::mem_fun(&Block::invalidate_transfer), block));
  block->m_transfers.clear();
}

BlockTransfer*
Block::find_queued(const PeerInfo* p) {
  transfer_list::iterator itr = std::find_if(m_queued.begin(), m_queued.end(), rak::equal(p, std::mem_fun(&BlockTransfer::peer_info)));

  if (itr == m_queued.end())
    return NULL;
  else
    return *itr;
}

const BlockTransfer*
Block::find_queued(const PeerInfo* p) const {
  transfer_list::const_iterator itr = std::find_if(m_queued.begin(), m_queued.end(), rak::equal(p, std::mem_fun(&BlockTransfer::peer_info)));

  if (itr == m_queued.end())
    return NULL;
  else
    return *itr;
}

BlockTransfer*
Block::find_transfer(const PeerInfo* p) {
  transfer_list::iterator itr = std::find_if(m_transfers.begin(), m_transfers.end(), rak::equal(p, std::mem_fun(&BlockTransfer::peer_info)));

  if (itr == m_transfers.end())
    return NULL;
  else
    return *itr;
}

const BlockTransfer*
Block::find_transfer(const PeerInfo* p) const {
  transfer_list::const_iterator itr = std::find_if(m_transfers.begin(), m_transfers.end(), rak::equal(p, std::mem_fun(&BlockTransfer::peer_info)));

  if (itr == m_transfers.end())
    return NULL;
  else
    return *itr;
}

}
