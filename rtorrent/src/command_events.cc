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

#include <functional>
#include <rak/file_stat.h>
#include <rak/path.h>
#include <sigc++/bind.h>
#include <torrent/rate.h>

#include "core/download.h"
#include "core/download_list.h"
#include "core/manager.h"
#include "utils/command_slot.h"
#include "utils/parse.h"

#include "globals.h"
#include "control.h"
#include "command_helpers.h"

torrent::Object
apply_on_state_change(core::DownloadList::slot_map* slotMap, const torrent::Object& rawArgs) {
  const torrent::Object::list_type& args = rawArgs.as_list();

  if (args.size() < 2)
    throw torrent::input_error("Too few arguments.");

  if (args.front().as_string().empty())
    throw torrent::input_error("Empty key.");

  std::string key = "1_state_" + args.front().as_string();

  if (args.back().as_string().empty())
    slotMap->erase(key);
  else
    (*slotMap)[key] = sigc::bind(sigc::mem_fun(control->download_variables(), &utils::VariableMap::process_d_std_single),
                                 utils::convert_list_to_command(++args.begin(), args.end()));

  return torrent::Object();
}

torrent::Object
apply_stop_on_ratio(const torrent::Object& rawArgs) {
  const torrent::Object::list_type& args = rawArgs.as_list();

  if (args.empty())
    throw torrent::input_error("Too few arguments.");

  torrent::Object::list_type::const_iterator argItr = args.begin();

  // first argument:  minimum ratio to reach
  // second argument: minimum upload amount to reach [optional]
  // third argument:  maximum ratio to reach [optional]
  int64_t minRatio  = utils::convert_to_value(*argItr++);
  int64_t minUpload = argItr != args.end() ? utils::convert_to_value(*argItr++) : 0;
  int64_t maxRatio  = argItr != args.end() ? utils::convert_to_value(*argItr++) : 0;

  core::DownloadList* downloadList = control->core()->download_list();
  core::Manager::DListItr itr = downloadList->begin();

  while ((itr = std::find_if(itr, downloadList->end(), std::mem_fun(&core::Download::is_seeding)))
         != downloadList->end()) {
    int64_t totalDone   = (*itr)->download()->bytes_done();
    int64_t totalUpload = (*itr)->download()->up_rate()->total();

    if ((totalUpload >= minUpload && totalUpload * 100 >= totalDone * minRatio) ||
        (maxRatio > 0 && totalUpload * 100 > totalDone * maxRatio)) {
      downloadList->stop_try(*itr);
      (*itr)->set("ignore_commands", (int64_t)1);
    }

    ++itr;
  }

  return torrent::Object();
}

torrent::Object
apply_start_tied() {
  for (core::DownloadList::iterator itr = control->core()->download_list()->begin(); itr != control->core()->download_list()->end(); ++itr) {
    if ((*itr)->get_value("state") == 1)
      continue;

    rak::file_stat fs;
    const std::string& tiedToFile = (*itr)->get_string("tied_to_file");

    if (!tiedToFile.empty() && fs.update(rak::path_expand(tiedToFile)))
      control->core()->download_list()->start_try(*itr);
  }

  return torrent::Object();
}

torrent::Object
apply_stop_untied() {
  for (core::DownloadList::iterator itr = control->core()->download_list()->begin(); itr != control->core()->download_list()->end(); ++itr) {
    if ((*itr)->get_value("state") == 0)
      continue;

    rak::file_stat fs;
    const std::string& tiedToFile = (*itr)->get_string("tied_to_file");

    if (!tiedToFile.empty() && !fs.update(rak::path_expand(tiedToFile)))
      control->core()->download_list()->stop_try(*itr);
  }

  return torrent::Object();
}

torrent::Object
apply_close_untied() {
  for (core::DownloadList::iterator itr = control->core()->download_list()->begin(); itr != control->core()->download_list()->end(); ++itr) {
    rak::file_stat fs;
    const std::string& tiedToFile = (*itr)->get_string("tied_to_file");

    if (!tiedToFile.empty() && !fs.update(rak::path_expand(tiedToFile)) && control->core()->download_list()->stop_try(*itr))
      control->core()->download_list()->close(*itr);
  }

  return torrent::Object();
}

torrent::Object
apply_remove_untied() {
  for (core::DownloadList::iterator itr = control->core()->download_list()->begin(); itr != control->core()->download_list()->end(); ) {
    rak::file_stat fs;
    const std::string& tiedToFile = (*itr)->get_string("tied_to_file");

    if (!tiedToFile.empty() && !fs.update(rak::path_expand(tiedToFile)) && control->core()->download_list()->stop_try(*itr))
      itr = control->core()->download_list()->erase(itr);
    else
      ++itr;
  }

  return torrent::Object();
}

void
initialize_command_events() {
  utils::VariableMap* variables = control->variable();
  core::DownloadList* downloadList = control->core()->download_list();

  ADD_COMMAND_SLOT("on_insert",       call_list, rak::bind_ptr_fn(&apply_on_state_change, &downloadList->slot_map_insert()));
  ADD_COMMAND_SLOT("on_erase",        call_list, rak::bind_ptr_fn(&apply_on_state_change, &downloadList->slot_map_erase()));
  ADD_COMMAND_SLOT("on_open",         call_list, rak::bind_ptr_fn(&apply_on_state_change, &downloadList->slot_map_open()));
  ADD_COMMAND_SLOT("on_close",        call_list, rak::bind_ptr_fn(&apply_on_state_change, &downloadList->slot_map_close()));
  ADD_COMMAND_SLOT("on_start",        call_list, rak::bind_ptr_fn(&apply_on_state_change, &downloadList->slot_map_start()));
  ADD_COMMAND_SLOT("on_stop",         call_list, rak::bind_ptr_fn(&apply_on_state_change, &downloadList->slot_map_stop()));
  ADD_COMMAND_SLOT("on_hash_queued",  call_list, rak::bind_ptr_fn(&apply_on_state_change, &downloadList->slot_map_hash_queued()));
  ADD_COMMAND_SLOT("on_hash_removed", call_list, rak::bind_ptr_fn(&apply_on_state_change, &downloadList->slot_map_hash_removed()));
  ADD_COMMAND_SLOT("on_hash_done",    call_list, rak::bind_ptr_fn(&apply_on_state_change, &downloadList->slot_map_hash_done()));
  ADD_COMMAND_SLOT("on_finished",     call_list, rak::bind_ptr_fn(&apply_on_state_change, &downloadList->slot_map_finished()));

  ADD_COMMAND_SLOT("stop_on_ratio",   call_list, rak::ptr_fn(&apply_stop_on_ratio));

  ADD_COMMAND_SLOT("start_tied",      call_string, utils::object_fn(&apply_start_tied));
  ADD_COMMAND_SLOT("stop_untied",     call_string, utils::object_fn(&apply_stop_untied));
  ADD_COMMAND_SLOT("close_untied",    call_string, utils::object_fn(&apply_close_untied));
  ADD_COMMAND_SLOT("remove_untied",   call_string, utils::object_fn(&apply_remove_untied));
}
