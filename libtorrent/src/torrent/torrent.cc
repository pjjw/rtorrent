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

#include <rak/address_info.h>
#include <rak/functional.h>
#include <rak/string_manip.h>

#include "exceptions.h"
#include "torrent.h"
#include "object.h"
#include "object_stream.h"
#include "throttle.h"
#include "connection_manager.h"
#include "poll.h"

#include "manager.h"
#include "resource_manager.h"

#include "protocol/handshake_manager.h"
#include "protocol/peer_factory.h"
#include "data/file_manager.h"
#include "data/hash_queue.h"
#include "data/hash_torrent.h"
#include "download/download_constructor.h"
#include "download/download_manager.h"
#include "download/download_wrapper.h"
#include "torrent/peer/connection_list.h"

namespace torrent {

uint32_t
calculate_max_open_files(uint32_t openMax) {
  if (openMax >= 8096)
    return 256;
  else if (openMax >= 1024)
    return 128;
  else if (openMax >= 512)
    return 64;
  else if (openMax >= 128)
    return 16;
  else // Assumes we don't try less than 64.
    return 4;
}

uint32_t
calculate_reserved(uint32_t openMax) {
  if (openMax >= 8096)
    return 256;
  else if (openMax >= 1024)
    return 128;
  else if (openMax >= 512)
    return 64;
  else if (openMax >= 128)
    return 32;
  else // Assumes we don't try less than 64.
    return 16;
}    

void
initialize(Poll* poll) {
  if (manager != NULL)
    throw internal_error("torrent::initialize(...) called but the library has already been initialized");

  if (poll->open_max() < 64)
    throw internal_error("Could not initialize libtorrent, Poll::open_max() < 64.");

  cachedTime = rak::timer::current();

  manager = new Manager;
  manager->set_poll(poll);

  uint32_t maxFiles = calculate_max_open_files(poll->open_max());

  manager->connection_manager()->set_max_size(poll->open_max() - maxFiles - calculate_reserved(poll->open_max()));
  manager->file_manager()->set_max_open_files(maxFiles);
}

// Clean up and close stuff. Stopping all torrents and waiting for
// them to finish is not required, but recommended.
void
cleanup() {
  if (manager == NULL)
    throw internal_error("torrent::cleanup() called but the library is not initialized.");

  delete manager;
  manager = NULL;
}

void
perform() {
  cachedTime = rak::timer::current();

  // Ensure we don't call rak::timer::current() twice if there was no
  // scheduled tasks called.
  if (taskScheduler.empty() || taskScheduler.top()->time() > cachedTime)
    return;

  while (!taskScheduler.empty() && taskScheduler.top()->time() <= cachedTime) {
    rak::priority_item* v = taskScheduler.top();
    taskScheduler.pop();

    v->clear_time();
    v->call();
  }

  // Update the timer again to ensure we get accurate triggering of
  // msec timers.
  cachedTime = rak::timer::current();
}

bool
is_inactive() {
  return manager == NULL ||
    std::find_if(manager->download_manager()->begin(), manager->download_manager()->end(), std::not1(std::mem_fun(&DownloadWrapper::is_stopped)))
    == manager->download_manager()->end();
}

ChunkManager*
chunk_manager() {
  return manager->chunk_manager();
}

ClientList*
client_list() {
  return manager->client_list();
}

ConnectionManager*
connection_manager() {
  return manager->connection_manager();
}

DhtManager*
dht_manager() {
  return manager->dht_manager();
}

uint32_t
total_handshakes() {
  return manager->handshake_manager()->size();
}

int64_t
next_timeout() {
  cachedTime = rak::timer::current();

  if (!taskScheduler.empty())
    return std::max(taskScheduler.top()->time() - cachedTime, rak::timer()).usec();
  else
    return rak::timer::from_seconds(60).usec();
}

Throttle*
down_throttle_global() {
  return manager->download_throttle();
}

Throttle*
up_throttle_global() {
  return manager->upload_throttle();
}

uint32_t
currently_unchoked() {
  return manager->resource_manager()->currently_upload_unchoked();
}

uint32_t
max_unchoked() {
  return manager->resource_manager()->max_upload_unchoked();
}

void
set_max_unchoked(uint32_t count) {
  if (count > (1 << 16))
    throw input_error("Max unchoked must be between 0 and 2^16.");

  manager->resource_manager()->set_max_upload_unchoked(count);
}

uint32_t
download_unchoked() {
  return manager->resource_manager()->currently_download_unchoked();
}

uint32_t
max_download_unchoked() {
  return manager->resource_manager()->max_download_unchoked();
}

void
set_max_download_unchoked(uint32_t count) {
  if (count > (1 << 16))
    throw input_error("Max unchoked must be between 0 and 2^16.");

  manager->resource_manager()->set_max_download_unchoked(count);
}

const Rate*
down_rate() {
  return manager->download_throttle()->rate();
}

const Rate*
up_rate() {
  return manager->upload_throttle()->rate();
}

const char*
version() {
  return VERSION;
}

uint32_t
hash_read_ahead() {
  return manager->hash_queue()->read_ahead();
}

void
set_hash_read_ahead(uint32_t bytes) {
  if (bytes < (1 << 20) || bytes > (64 << 20))
    throw input_error("Hash read ahead must be between 1 and 64 MB.");

  manager->hash_queue()->set_read_ahead(bytes);
}

uint32_t
hash_interval() {
  return manager->hash_queue()->interval();
}

void
set_hash_interval(uint32_t usec) {
  if (usec < (1 * 1000) || usec > (1000 * 1000))
    throw input_error("Hash interval must be between 1 and 1000 ms.");

  manager->hash_queue()->set_interval(usec);
}

uint32_t
hash_max_tries() {
  return manager->hash_queue()->max_tries();
}

void
set_hash_max_tries(uint32_t tries) {
  if (tries > 100)
    throw input_error("Hash max tries must be between 0 and 100.");

  manager->hash_queue()->set_max_tries(tries);
}  

uint32_t
open_files() {
  return manager->file_manager()->open_files();
}

uint32_t
max_open_files() {
  return manager->file_manager()->max_open_files();
}

void
set_max_open_files(uint32_t size) {
  if (size < 4 || size > (1 << 16))
    throw input_error("Max open files must be between 4 and 2^16.");

  manager->file_manager()->set_max_open_files(size);
}

EncodingList*
encoding_list() {
  return manager->encoding_list();
}

Download
download_add(Object* object) {
  std::auto_ptr<DownloadWrapper> download(new DownloadWrapper);

  DownloadConstructor ctor;
  ctor.set_download(download.get());
  ctor.set_encoding_list(manager->encoding_list());

  ctor.initialize(*object);

  std::string infoHash = object_sha1(&object->get_key("info"));

  if (manager->download_manager()->find(infoHash) != manager->download_manager()->end())
    throw input_error("Info hash already used by another torrent.");

  download->set_hash_queue(manager->hash_queue());
  download->initialize(infoHash, PEER_NAME + rak::generate_random<std::string>(20 - std::string(PEER_NAME).size()));

  // Default PeerConnection factory functions.
  download->main()->connection_list()->slot_new_connection(&createPeerConnectionDefault);

  // Consider move as much as possible into this function
  // call. Anything that won't cause possible torrent creation errors
  // go in there.
  manager->initialize_download(download.get());

  download->set_bencode(object);
  return Download(download.release());
}

void
download_remove(Download d) {
  manager->cleanup_download(d.ptr());
}

// Add all downloads to dlist. Make sure it's cleared.
void
download_list(DList& dlist) {
  for (DownloadManager::const_iterator itr = manager->download_manager()->begin();
       itr != manager->download_manager()->end(); ++itr)
    dlist.push_back(Download(*itr));
}

// Make sure you check that it's valid.
Download
download_find(const std::string& infohash) {
  return *manager->download_manager()->find(infohash);
}

uint32_t
download_priority(Download d) {
  ResourceManager::iterator itr = manager->resource_manager()->find(d.ptr()->main());

  if (itr == manager->resource_manager()->end())
    throw internal_error("torrent::download_priority(...) could not find the download in the resource manager.");

  return itr->first;
}

void
download_set_priority(Download d, uint32_t pri) {
  ResourceManager::iterator itr = manager->resource_manager()->find(d.ptr()->main());

  if (itr == manager->resource_manager()->end())
    throw internal_error("torrent::download_set_priority(...) could not find the download in the resource manager.");

  if (pri > 1024)
    throw internal_error("torrent::download_set_priority(...) received an invalid priority.");

  manager->resource_manager()->set_priority(itr, pri);
}

}
