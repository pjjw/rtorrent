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

// Provides a filtered and sorted list of downloads that can be
// updated auto-magically.
//
// We don't worry about std::vector's insert/erase performance as the
// elements get accessed often but not modified, better with cache
// locality.
//
// ViewDownloads::m_size indicates the number of Download's that
// remain visible, e.g. has not been filtered out. The Download's that
// were filtered are still in the underlying vector, but cannot be
// accessed through the normal stl container functions.

#ifndef RTORRENT_CORE_VIEW_DOWNLOADS_H
#define RTORRENT_CORE_VIEW_DOWNLOADS_H

#include <memory>
#include <string>
#include <vector>
#include <rak/timer.h>
#include <sigc++/signal.h>

#include "globals.h"

namespace core {

class Download;
class DownloadList;
class ViewSort;
class ViewFilter;

class ViewDownloads : public std::vector<core::Download*> {
public:
  typedef std::vector<core::Download*>   base_type;
  typedef sigc::signal0<void>            signal_type;
  typedef std::vector<const ViewSort*>   sort_list;
  typedef std::vector<const ViewFilter*> filter_list;

  using base_type::iterator;
  using base_type::const_iterator;
  using base_type::reverse_iterator;
  using base_type::const_reverse_iterator;
  
  using base_type::size_type;

  using base_type::begin;
  using base_type::rbegin;

  ViewDownloads() {}
  ~ViewDownloads();

  void                initialize(const std::string& name, core::DownloadList* list);

  const std::string&  name() const                            { return m_name; }

  bool                empty() const                           { return m_size == 0; }
  size_type           size() const                            { return m_size; }

  // Perhaps this should be renamed?
  iterator            end()                                   { return begin() + m_size; }
  const_iterator      end() const                             { return begin() + m_size; }

//   using base_type::rend;

  iterator            end_filtered()                          { return base_type::end(); }
  const_iterator      end_filtered() const                    { return base_type::end(); }

  iterator            focus()                                 { return begin() + m_focus; }
  const_iterator      focus() const                           { return begin() + m_focus; }
  void                set_focus(iterator itr)                 { m_focus = position(itr); m_signalChanged.emit(); }

  void                next_focus();
  void                prev_focus();

  void                sort();

  void                set_sort_new(const sort_list& s)        { m_sortNew = s; }
  void                set_sort_current(const sort_list& s)    { m_sortCurrent = s; }

  // Need to explicity trigger filtering.
  void                filter();
  void                set_filter(const filter_list& s)        { m_filter = s; }

  // The time of the last change to the view, semantics of this is
  // user-dependent. Used by f.ex. ViewManager to decide if it should
  // sort and/or filter a view.
  //
  // Currently initialized to rak::timer(), though perhaps we should
  // use cachedTimer.
  rak::timer          last_changed() const                                 { return m_lastChanged; }
  void                set_last_changed(const rak::timer& t = ::cachedTime) { m_lastChanged = t; }

  // Don't connect any slots until after initialize else it get's
  // triggered when adding the Download's in DownloadList.
  signal_type&        signal_changed()                        { return m_signalChanged; }

private:
  ViewDownloads(const ViewDownloads&);
  void operator = (const ViewDownloads&);

  void                received_insert(core::Download* d);
  void                received_erase(core::Download* d);

  size_type           position(const_iterator itr) const      { return itr - begin(); }

  // An received thing for changed status so we can sort and filter.

  std::string         m_name;

  core::DownloadList* m_list;

  size_type           m_size;
  size_type           m_focus;

  sort_list           m_sortNew;
  sort_list           m_sortCurrent;

  filter_list         m_filter;

  rak::timer          m_lastChanged;
  signal_type         m_signalChanged;
};

class ViewSort {
public:
  virtual ~ViewSort() {}

  virtual bool operator () (Download* d1, Download* d2) const = 0;
};

class ViewFilter {
public:
  virtual ~ViewFilter() {}

  virtual bool operator () (Download* d1) const = 0;
};

}

#endif
