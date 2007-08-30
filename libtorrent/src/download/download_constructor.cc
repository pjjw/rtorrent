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

#include <cstring>
#include <strings.h>
#include <rak/functional.h>
#include <rak/string_manip.h>

#include "download/download_wrapper.h"
#include "torrent/exceptions.h"
#include "torrent/object.h"
#include "torrent/data/file.h"
#include "torrent/data/file_list.h"
#include "tracker/tracker_manager.h"

#include "download_constructor.h"

namespace torrent {

struct download_constructor_is_single_path {
  bool operator () (Object::map_type::const_reference v) const {
    return
      std::strncmp(v.first.c_str(), "name.", sizeof("name.") - 1) == 0 &&
      v.second.is_string();
  }
};

struct download_constructor_is_multi_path {
  bool operator () (Object::map_type::const_reference v) const {
    return
      std::strncmp(v.first.c_str(), "path.", sizeof("path.") - 1) == 0 &&
      v.second.is_list();
  }
};

struct download_constructor_encoding_match :
    public std::binary_function<const Path&, const char*, bool> {

  bool operator () (const Path& p, const char* enc) {
    return strcasecmp(p.encoding().c_str(), enc) == 0;
  }
};

void
DownloadConstructor::initialize(const Object& b) {
  if (b.has_key_string("encoding"))
    m_defaultEncoding = b.get_key_string("encoding");

  m_download->info()->set_private(b.get_key("info").has_key_value("private") && 
                                  b.get_key("info").get_key_value("private") == 1);

  parse_name(b.get_key("info"));
  parse_info(b.get_key("info"));

  parse_tracker(b);
}

// Currently using a hack of the path thingie to extract the correct
// torrent name.
void
DownloadConstructor::parse_name(const Object& b) {
  if (is_invalid_path_element(b.get_key("name")))
    throw input_error("Bad torrent file, \"name\" is an invalid path name.");

  std::list<Path> pathList;

  pathList.push_back(Path());
  pathList.back().set_encoding(m_defaultEncoding);
  pathList.back().push_back(b.get_key_string("name"));

  for (Object::map_type::const_iterator itr = b.as_map().begin();
       (itr = std::find_if(itr, b.as_map().end(), download_constructor_is_single_path())) != b.as_map().end();
       ++itr) {
    pathList.push_back(Path());
    pathList.back().set_encoding(itr->first.substr(sizeof("name.") - 1));
    pathList.back().push_back(itr->second.as_string());
  }

  if (pathList.empty())
    throw input_error("Bad torrent file, an entry has no valid name.");

  Path name = choose_path(&pathList);

  if (name.empty())
    throw internal_error("DownloadConstructor::parse_name(...) Ended up with an empty Path.");

  m_download->info()->set_name(name.front());
}

void
DownloadConstructor::parse_info(const Object& b) {
  FileList* fileList = m_download->main()->file_list();

  if (!fileList->empty())
    throw internal_error("parse_info received an already initialized Content object.");

  uint32_t chunkSize = b.get_key_value("piece length");

  if (chunkSize <= (1 << 10) || chunkSize > (128 << 20))
    throw input_error("Torrent has an invalid \"piece length\".");

  if (b.has_key("length")) {
    parse_single_file(b, chunkSize);

  } else if (b.has_key("files")) {
    parse_multi_files(b.get_key("files"), chunkSize);
    fileList->set_root_dir("./" + m_download->info()->name());

  } else {
    throw input_error("Torrent must have either length or files entry.");
  }

  if (fileList->size_bytes() == 0)
    throw input_error("Torrent has zero length.");

  // Set chunksize before adding files to make sure the index range is
  // correct.
  m_download->set_complete_hash(b.get_key_string("pieces"));

  if (m_download->complete_hash().size() / 20 < fileList->size_chunks())
    throw bencode_error("Torrent size and 'info:pieces' length does not match.");
}

void
DownloadConstructor::parse_tracker(const Object& b) {
  TrackerManager* tracker = m_download->main()->tracker_manager();

  if (b.has_key_list("announce-list"))
    std::for_each(b.get_key_list("announce-list").begin(), b.get_key_list("announce-list").end(),
		  rak::make_mem_fun(this, &DownloadConstructor::add_tracker_group));

  else if (b.has_key("announce"))
    add_tracker_single(b.get_key("announce"), 0);

  else
    throw bencode_error("Could not find any trackers");

  tracker->randomize();
}

void
DownloadConstructor::add_tracker_group(const Object& b) {
  if (!b.is_list())
    throw bencode_error("Tracker group list not a list");

  std::for_each(b.as_list().begin(), b.as_list().end(),
		rak::bind2nd(rak::make_mem_fun(this, &DownloadConstructor::add_tracker_single),
			     m_download->main()->tracker_manager()->group_size()));
}

void
DownloadConstructor::add_tracker_single(const Object& b, int group) {
  if (!b.is_string())
    throw bencode_error("Tracker entry not a string");
    
  m_download->main()->tracker_manager()->insert(group, rak::trim_classic(b.as_string()));
}

bool
DownloadConstructor::is_valid_path_element(const Object& b) {
  return
    b.is_string() &&
    b.as_string() != "." &&
    b.as_string() != ".." &&
    std::find(b.as_string().begin(), b.as_string().end(), '/') == b.as_string().end() &&
    std::find(b.as_string().begin(), b.as_string().end(), '\0') == b.as_string().end();
}

void
DownloadConstructor::parse_single_file(const Object& b, uint32_t chunkSize) {
  if (is_invalid_path_element(b.get_key("name")))
    throw input_error("Bad torrent file, \"name\" is an invalid path name.");

  FileList* fileList = m_download->main()->file_list();
  fileList->initialize(b.get_key_value("length"), chunkSize);
  fileList->set_multi_file(false);

  std::list<Path> pathList;

  pathList.push_back(Path());
  pathList.back().set_encoding(m_defaultEncoding);
  pathList.back().push_back(b.get_key_string("name"));

  for (Object::map_type::const_iterator itr = b.as_map().begin();
       (itr = std::find_if(itr, b.as_map().end(), download_constructor_is_single_path())) != b.as_map().end();
       ++itr) {
    pathList.push_back(Path());
    pathList.back().set_encoding(itr->first.substr(sizeof("name.") - 1));
    pathList.back().push_back(itr->second.as_string());
  }

  if (pathList.empty())
    throw input_error("Bad torrent file, an entry has no valid filename.");

  *fileList->front()->path() = choose_path(&pathList);
  fileList->update_paths(fileList->begin(), fileList->end());  
}

void
DownloadConstructor::parse_multi_files(const Object& b, uint32_t chunkSize) {
  const Object::list_type& objectList = b.as_list();

  // Multi file torrent
  if (objectList.empty())
    throw input_error("Bad torrent file, entry has no files.");

  int64_t torrentSize = 0;
  std::vector<FileList::split_type> splitList(objectList.size());
  std::vector<FileList::split_type>::iterator splitItr = splitList.begin();

  for (Object::list_type::const_iterator listItr = objectList.begin(), listLast = objectList.end(); listItr != listLast; ++listItr, ++splitItr) {
    std::list<Path> pathList;

    if (listItr->has_key_list("path"))
      pathList.push_back(create_path(listItr->get_key_list("path"), m_defaultEncoding));

    Object::map_type::const_iterator itr = listItr->as_map().begin();
    Object::map_type::const_iterator last = listItr->as_map().end();
  
    while ((itr = std::find_if(itr, last, download_constructor_is_multi_path())) != last) {
      pathList.push_back(create_path(itr->second.as_list(), itr->first.substr(sizeof("path.") - 1)));
      ++itr;
    }

    if (pathList.empty())
      throw input_error("Bad torrent file, an entry has no valid filename.");

    int64_t length = listItr->get_key_value("length");

    if (length < 0 || torrentSize + length < 0)
      throw input_error("Bad torrent file, invalid length for file.");

    torrentSize += length;
    *splitItr = FileList::split_type(length, choose_path(&pathList));
  }

  FileList* fileList = m_download->main()->file_list();
  fileList->set_multi_file(true);

  fileList->initialize(torrentSize, chunkSize);
  fileList->split(fileList->begin(), &*splitList.begin(), &*splitList.end());
  fileList->update_paths(fileList->begin(), fileList->end());  
}

inline Path
DownloadConstructor::create_path(const Object::list_type& plist, const std::string enc) {
  // Make sure we are given a proper file path.
  if (plist.empty())
    throw input_error("Bad torrent file, \"path\" has zero entries.");

  if (std::find_if(plist.begin(), plist.end(), std::ptr_fun(&DownloadConstructor::is_invalid_path_element)) != plist.end())
    throw input_error("Bad torrent file, \"path\" has zero entries or a zero lenght entry.");

  Path p;
  p.set_encoding(enc);

  std::transform(plist.begin(), plist.end(), std::back_inserter(p), std::mem_fun_ref<const Object::string_type&>(&Object::as_string));

  return p;
}

inline Path
DownloadConstructor::choose_path(std::list<Path>* pathList) {
  std::list<Path>::iterator pathFirst        = pathList->begin();
  std::list<Path>::iterator pathLast         = pathList->end();
  EncodingList::const_iterator encodingFirst = m_encodingList->begin();
  EncodingList::const_iterator encodingLast  = m_encodingList->end();
  
  for ( ; encodingFirst != encodingLast; ++encodingFirst) {
    std::list<Path>::iterator itr = std::find_if(pathFirst, pathLast, rak::bind2nd(download_constructor_encoding_match(), encodingFirst->c_str()));
    
    if (itr != pathLast)
      pathList->splice(pathFirst, *pathList, itr);
  }

  return pathList->front();
}

}
