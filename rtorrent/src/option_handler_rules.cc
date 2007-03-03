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

#include <cstdio>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <rak/file_stat.h>
#include <rak/fs_stat.h>
#include <rak/functional.h>
#include <rak/path.h>
#include <rak/string_manip.h>
#include <sigc++/bind.h>
#include <torrent/object.h>
#include <torrent/chunk_manager.h>
#include <torrent/connection_manager.h>
#include <torrent/exceptions.h>
#include <torrent/path.h>
#include <torrent/rate.h>
#include <torrent/torrent.h>
#include <torrent/tracker.h>
#include <torrent/tracker_list.h>
#include <torrent/data/file.h>
#include <torrent/data/file_list.h>

#include "core/download.h"
#include "core/download_list.h"
#include "core/download_store.h"
#include "core/manager.h"
#include "core/scheduler.h"
#include "core/view_manager.h"
#include "ui/root.h"
#include "utils/directory.h"
#include "utils/variable_generic.h"
#include "utils/variable_map.h"

#include "globals.h"
#include "control.h"
#include "option_handler_rules.h"
#include "command_scheduler.h"

namespace core {
  extern void
  path_expand(std::vector<std::string>* paths, const std::string& pattern);
}

// void
// apply_new_string(const std::string& args) {
//   std::string::const_iterator split = std::find(args.begin(), args.end(), ',');

//   std::string key = 

//   if (control->variable()->has(args))

//   variables->insert("tracker_dump",          new utils::VariableAny(std::string()));
// }

void
apply_hash_read_ahead(int arg) {
  torrent::set_hash_read_ahead(arg << 20);
}

void
apply_hash_interval(int arg) {
  torrent::set_hash_interval(arg * 1000);
}

// The arg string *must* have been checked with validate_port_range
// first.
void
apply_port_range(const std::string& arg) {
  int a = 0, b = 0;
    
  std::sscanf(arg.c_str(), "%i-%i", &a, &b);

  control->core()->set_port_range(a, b);
}

void
apply_load(const std::string& arg) {
  control->core()->try_create_download_expand(arg, false, false, true);
}

void
apply_load_verbose(const std::string& arg) {
  control->core()->try_create_download_expand(arg, false, true, true);
}

void
apply_load_start(const std::string& arg) {
  control->core()->try_create_download_expand(arg, true, false, true);
}

void
apply_load_start_verbose(const std::string& arg) {
  control->core()->try_create_download_expand(arg, true, true, true);
}

void
apply_start_tied() {
  for (core::DownloadList::iterator itr = control->core()->download_list()->begin(); itr != control->core()->download_list()->end(); ++itr) {
    if ((*itr)->get_value("state") == 1)
      continue;

    rak::file_stat fs;
    const std::string& tiedToFile = (*itr)->get_string("tied_to_file");

    if (!tiedToFile.empty() && fs.update(rak::path_expand(tiedToFile)))
      control->core()->download_list()->start_try(*itr);
  }
}

void
apply_stop_untied() {
  for (core::DownloadList::iterator itr = control->core()->download_list()->begin(); itr != control->core()->download_list()->end(); ++itr) {
    if ((*itr)->get_value("state") == 0)
      continue;

    rak::file_stat fs;
    const std::string& tiedToFile = (*itr)->get_string("tied_to_file");

    if (!tiedToFile.empty() && !fs.update(rak::path_expand(tiedToFile)))
      control->core()->download_list()->stop_try(*itr);
  }
}

void
apply_close_untied() {
  for (core::DownloadList::iterator itr = control->core()->download_list()->begin(); itr != control->core()->download_list()->end(); ++itr) {
    rak::file_stat fs;
    const std::string& tiedToFile = (*itr)->get_string("tied_to_file");

    if (!tiedToFile.empty() && !fs.update(rak::path_expand(tiedToFile)) && control->core()->download_list()->stop_try(*itr))
      control->core()->download_list()->close(*itr);
  }
}

void
apply_remove_untied() {
  for (core::DownloadList::iterator itr = control->core()->download_list()->begin(); itr != control->core()->download_list()->end(); ) {
    rak::file_stat fs;
    const std::string& tiedToFile = (*itr)->get_string("tied_to_file");

    if (!tiedToFile.empty() && !fs.update(rak::path_expand(tiedToFile)) && control->core()->download_list()->stop_try(*itr))
      itr = control->core()->download_list()->erase(itr);
    else
      ++itr;
  }
}

void
apply_close_low_diskspace(int64_t arg) {
  core::Manager::DListItr itr = control->core()->download_list()->begin();

  while ((itr = std::find_if(itr, control->core()->download_list()->end(), std::mem_fun(&core::Download::is_downloading))) != control->core()->download_list()->end()) {
    if ((*itr)->file_list()->free_diskspace() < (uint64_t)arg) {
      control->core()->download_list()->close(*itr);

      (*itr)->set_hash_failed(true);
      (*itr)->set_message(std::string("Low diskspace."));
    }

    ++itr;
  }
}

void
apply_stop_on_ratio(const std::string& arg) {
  int64_t minRatio = 0;  // first argument:  minimum ratio to reach
  int64_t minUpload = 0; // second argument: minimum upload amount to reach [optional]
  int64_t maxRatio = 0;  // third argument:  maximum ratio to reach [optional]

  rak::split_iterator_t<std::string> sitr = rak::split_iterator(arg, ',');

  utils::Variable::string_to_value_unit(rak::trim(*sitr).c_str(), &minRatio, 0, 1);

  if (++sitr != rak::split_iterator(arg))
    utils::Variable::string_to_value_unit(rak::trim(*sitr).c_str(), &minUpload, 0, 1);

  if (++sitr != rak::split_iterator(arg))
    utils::Variable::string_to_value_unit(rak::trim(*sitr).c_str(), &maxRatio, 0, 1);

  core::Manager::DListItr itr = control->core()->download_list()->begin();

  while ((itr = std::find_if(itr, control->core()->download_list()->end(), std::mem_fun(&core::Download::is_seeding))) != control->core()->download_list()->end()) {
    int64_t totalUpload = (*itr)->download()->up_rate()->total();
    int64_t totalDone = (*itr)->download()->bytes_done();

    if ((totalUpload >= minUpload && totalUpload * 100 >= totalDone * minRatio) || (maxRatio > 0 && totalUpload * 100 > totalDone * maxRatio)) {
      control->core()->download_list()->stop_try(*itr);
      (*itr)->set("ignore_commands", (int64_t)1);
    }

    ++itr;
  }
}

void
apply_on_state_change(core::DownloadList::slot_map* slotMap, const std::string& arg) {
  std::string::const_iterator itr = std::find(arg.begin(), arg.end(), ',');

  std::string key   = rak::trim(std::string(arg.begin(), itr));
  std::string value = rak::trim(std::string(itr != arg.end() ? itr + 1 : itr, arg.end()));

  if (key.empty())
    throw torrent::input_error("Empty key.");

  if (value.empty())
    slotMap->erase("1_start_" + key);
  else
    (*slotMap)["1_start_" + key] = sigc::bind(sigc::mem_fun(control->download_variables(), &utils::VariableMap::process_d_std_single), value);
}

void
apply_encoding_list(const std::string& arg) {
  torrent::encoding_list()->push_back(arg);
}

void
apply_encryption(const std::string& arg) {
  rak::split_iterator_t<std::string> sitr = rak::split_iterator(arg, ',');
  uint32_t options_mask = torrent::ConnectionManager::encryption_none;

  while (sitr != rak::split_iterator(arg)) {
    std::string opt = rak::trim(*sitr);
    ++sitr;

    if (opt == "none")
      options_mask = torrent::ConnectionManager::encryption_none;
    else if (opt == "allow_incoming")
      options_mask |= torrent::ConnectionManager::encryption_allow_incoming;
    else if (opt == "try_outgoing")
      options_mask |= torrent::ConnectionManager::encryption_try_outgoing;
    else if (opt == "require")
      options_mask |= torrent::ConnectionManager::encryption_require;
    else if (opt == "require_RC4" || opt == "require_rc4")
      options_mask |= torrent::ConnectionManager::encryption_require_RC4;
    else if (opt == "enable_retry")
      options_mask |= torrent::ConnectionManager::encryption_enable_retry;
    else if (opt == "prefer_plaintext")
      options_mask |= torrent::ConnectionManager::encryption_prefer_plaintext;
    else
      throw torrent::input_error("Invalid encryption option '" + opt + "'.");
  }

  torrent::connection_manager()->set_encryption_options(options_mask);
}

void
apply_enable_trackers(__UNUSED const std::string& arg) {
  bool state = (arg != "no");

  for (core::Manager::DListItr itr = control->core()->download_list()->begin(), last = control->core()->download_list()->end(); itr != last; ++itr) {

    torrent::TrackerList tl = (*itr)->download()->tracker_list();

    for (int i = 0, last = tl.size(); i < last; ++i)
      if (state)
        tl.get(i).enable();
      else
        tl.get(i).disable();

    if (state && !control->variable()->get_value("use_udp_trackers"))
      (*itr)->enable_udp_trackers(false);
  }    
}

void
apply_tos(const std::string& arg) {
  utils::Variable::value_type value;
  torrent::ConnectionManager* cm = torrent::connection_manager();

  if (arg == "default")
    value = torrent::ConnectionManager::iptos_default;

  else if (arg == "lowdelay")
    value = torrent::ConnectionManager::iptos_lowdelay;

  else if (arg == "throughput")
    value = torrent::ConnectionManager::iptos_throughput;

  else if (arg == "reliability")
    value = torrent::ConnectionManager::iptos_reliability;

  else if (arg == "mincost")
    value = torrent::ConnectionManager::iptos_mincost;

  else if (!utils::Variable::string_to_value_unit_nothrow(arg.c_str(), &value, 16, 1))
    throw torrent::input_error("Invalid TOS identifier.");

  cm->set_priority(value);
}

void
apply_view_filter(const std::string& arg) {
  rak::split_iterator_t<std::string> itr = rak::split_iterator(arg, ',');

  std::string name = rak::trim(*itr);
  
  if (name.empty())
    throw torrent::input_error("First argument must be a string.");

  core::ViewManager::filter_args filterArgs;

  while (++itr != rak::split_iterator(arg)) {
    filterArgs.push_back(rak::trim(*itr));

    if (filterArgs.back().empty())
      throw torrent::input_error("One of the arguments is empty.");
  }

  control->view_manager()->set_filter(name, filterArgs);
}

void
apply_view_filter_on(const std::string& arg) {
  rak::split_iterator_t<std::string> itr = rak::split_iterator(arg, ',');

  std::string name = rak::trim(*itr);
  
  if (name.empty())
    throw torrent::input_error("First argument must be a string.");

  core::ViewManager::filter_args filterArgs;

  while (++itr != rak::split_iterator(arg)) {
    filterArgs.push_back(rak::trim(*itr));

    if (filterArgs.back().empty())
      throw torrent::input_error("One of the arguments is empty.");
  }

  control->view_manager()->set_filter_on(name, filterArgs);
}

void
apply_view_sort(const std::string& arg) {
  rak::split_iterator_t<std::string> itr = rak::split_iterator(arg, ',');

  std::string name = rak::trim(*itr);
  ++itr;

  if (name.empty())
    throw torrent::input_error("First argument must be a string.");

  // Need some generic tools for this, rather than hacking up
  // something every time...
  std::string arg1;
  int32_t value = 0;

  if (itr != rak::split_iterator(arg) && !(arg1 = *itr).empty()) {
    char* endPtr;

    if ((value = strtol(arg1.c_str(), &endPtr, 0)) < 0 || *endPtr != '\0')
      throw torrent::input_error("Second argument must be a value.");
  }
      
  control->view_manager()->sort(name, value);
}

void
apply_view_sort_current(const std::string& arg) {
  rak::split_iterator_t<std::string> itr = rak::split_iterator(arg, ',');

  std::string name = rak::trim(*itr);
  
  if (name.empty())
    throw torrent::input_error("First argument must be a string.");

  core::ViewManager::sort_args sortArgs;

  while (++itr != rak::split_iterator(arg)) {
    sortArgs.push_back(rak::trim(*itr));

    if (sortArgs.back().empty())
      throw torrent::input_error("One of the arguments is empty.");
  }

  control->view_manager()->set_sort_current(name, sortArgs);
}

void
apply_view_sort_new(const std::string& arg) {
  rak::split_iterator_t<std::string> itr = rak::split_iterator(arg, ',');

  std::string name = rak::trim(*itr);
  
  if (name.empty())
    throw torrent::input_error("First argument must be a string.");

  core::ViewManager::sort_args sortArgs;

  while (++itr != rak::split_iterator(arg)) {
    sortArgs.push_back(rak::trim(*itr));

    if (sortArgs.back().empty())
      throw torrent::input_error("One of the arguments is empty.");
  }

  control->view_manager()->set_sort_new(name, sortArgs);
}

void
apply_import(const std::string& path) {
  if (!control->variable()->process_file(path.c_str()))
    throw torrent::input_error("Could not open option file: " + path);
}

void
apply_try_import(const std::string& path) {
  if (!control->variable()->process_file(path.c_str()))
    control->core()->push_log("Could not read resource file: " + path);
}

void
initialize_variables() {
  utils::VariableMap* variables = control->variable();

  variables->insert("check_hash",            new utils::VariableBool(true));
  variables->insert("use_udp_trackers",      new utils::VariableBool(true));
  variables->insert("port_open",             new utils::VariableBool(true));
  variables->insert("port_random",           new utils::VariableBool(true));

  variables->insert("tracker_dump",          new utils::VariableAny(std::string()));

  variables->insert("session",               new utils::VariableStringSlot(rak::mem_fn(control->core()->download_store(), &core::DownloadStore::path),
                                                                           rak::mem_fn(control->core()->download_store(), &core::DownloadStore::set_path)));
  variables->insert("session_lock",          new utils::VariableBool(true));
  variables->insert("session_on_completion", new utils::VariableBool(true));
  variables->insert("session_save",          new utils::VariableVoidSlot(rak::mem_fn(control->core()->download_list(), &core::DownloadList::session_save)));

  variables->insert("connection_leech",      new utils::VariableAny("leech"));
  variables->insert("connection_seed",       new utils::VariableAny("seed"));

  variables->insert("directory",             new utils::VariableAny("./"));

  variables->insert("tos",                   new utils::VariableStringSlot(NULL, rak::ptr_fn(&apply_tos)));

  variables->insert("bind",                  new utils::VariableStringSlot(rak::mem_fn(control->core(), &core::Manager::bind_address),
                                                                           rak::mem_fn(control->core(), &core::Manager::set_bind_address)));
  variables->insert("ip",                    new utils::VariableStringSlot(rak::mem_fn(control->core(), &core::Manager::local_address),
                                                                           rak::mem_fn(control->core(), &core::Manager::set_local_address)));
  variables->insert("connection_proxy",      new utils::VariableStringSlot(rak::mem_fn(control->core(), &core::Manager::proxy_address),
                                                                           rak::mem_fn(control->core(), &core::Manager::set_proxy_address)));

  variables->insert("http_proxy",            new utils::VariableStringSlot(rak::mem_fn(control->core()->get_poll_manager()->get_http_stack(), &core::CurlStack::http_proxy),
                                                                           rak::mem_fn(control->core()->get_poll_manager()->get_http_stack(), &core::CurlStack::set_http_proxy)));

  variables->insert("min_peers",             new utils::VariableValue(40));
  variables->insert("max_peers",             new utils::VariableValue(100));
  variables->insert("min_peers_seed",        new utils::VariableValue(-1));
  variables->insert("max_peers_seed",        new utils::VariableValue(-1));
  variables->insert("max_uploads",           new utils::VariableValue(15));
  variables->insert("max_uploads_div",       new utils::VariableValue(1));
  variables->insert("max_chunks_queued",     new utils::VariableValue(0));

  variables->insert("max_downloads_hack",    new utils::VariableValueSlot(rak::ptr_fn(&torrent::max_download_unchoked), rak::ptr_fn(&torrent::set_max_download_unchoked)));

  variables->insert("download_rate",         new utils::VariableValueSlot(rak::ptr_fn(&torrent::down_throttle), rak::mem_fn(control->ui(), &ui::Root::set_down_throttle_i64),
                                                                          0, (1 << 10)));
  variables->insert("upload_rate",           new utils::VariableValueSlot(rak::ptr_fn(&torrent::up_throttle), rak::mem_fn(control->ui(), &ui::Root::set_up_throttle_i64),
                                                                          0, (1 << 10)));

  variables->insert("tracker_numwant",       new utils::VariableValue(-1));

  variables->insert("hash_max_tries",        new utils::VariableValueSlot(rak::ptr_fn(&torrent::hash_max_tries), rak::ptr_fn(&torrent::set_hash_max_tries)));
  variables->insert("max_open_files",        new utils::VariableValueSlot(rak::ptr_fn(&torrent::max_open_files), rak::ptr_fn(&torrent::set_max_open_files)));
  variables->insert("max_open_sockets",      new utils::VariableValueSlot(rak::mem_fn(torrent::connection_manager(), &torrent::ConnectionManager::max_size),
                                                                          rak::mem_fn(torrent::connection_manager(), &torrent::ConnectionManager::set_max_size)));
  variables->insert("max_open_http",         new utils::VariableValueSlot(rak::mem_fn(control->core()->get_poll_manager()->get_http_stack(), &core::CurlStack::max_active),
                                                                          rak::mem_fn(control->core()->get_poll_manager()->get_http_stack(), &core::CurlStack::set_max_active)));

  variables->insert("print",                 new utils::VariableStringSlot(NULL, rak::mem_fn(control->core(), &core::Manager::push_log)));
  variables->insert("import",                new utils::VariableStringSlot(NULL, rak::ptr_fn(&apply_import)));
  variables->insert("try_import",            new utils::VariableStringSlot(NULL, rak::ptr_fn(&apply_try_import)));

  variables->insert("view_add",              new utils::VariableStringSlot(NULL, rak::mem_fn(control->view_manager(), &core::ViewManager::insert_throw)));
  variables->insert("view_filter",           new utils::VariableStringSlot(NULL, rak::ptr_fn(&apply_view_filter)));
  variables->insert("view_filter_on",        new utils::VariableStringSlot(NULL, rak::ptr_fn(&apply_view_filter_on)));

  variables->insert("view_sort",             new utils::VariableStringSlot(NULL, rak::ptr_fn(&apply_view_sort)));
  variables->insert("view_sort_new",         new utils::VariableStringSlot(NULL, rak::ptr_fn(&apply_view_sort_new)));
  variables->insert("view_sort_current",     new utils::VariableStringSlot(NULL, rak::ptr_fn(&apply_view_sort_current)));

  variables->insert("key_layout",            new utils::VariableAny(std::string("qwerty")));

  variables->insert("schedule",              new utils::VariableStringSlot(NULL, rak::mem_fn(control->command_scheduler(), &CommandScheduler::parse)));
  variables->insert("schedule_remove",       new utils::VariableStringSlot(NULL,
                                                                           rak::mem_fn<const std::string&>(control->command_scheduler(), &CommandScheduler::erase)));

  variables->insert("download_scheduler",    new utils::VariableVoidSlot(rak::mem_fn(control->scheduler(), &core::Scheduler::update)));

  variables->insert("send_buffer_size",      new utils::VariableValueSlot(rak::mem_fn(torrent::connection_manager(), &torrent::ConnectionManager::send_buffer_size),
                                                                          rak::mem_fn(torrent::connection_manager(), &torrent::ConnectionManager::set_send_buffer_size)));
  
  variables->insert("receive_buffer_size",   new utils::VariableValueSlot(rak::mem_fn(torrent::connection_manager(), &torrent::ConnectionManager::receive_buffer_size),
                                                                          rak::mem_fn(torrent::connection_manager(), &torrent::ConnectionManager::set_receive_buffer_size)));
  
  variables->insert("max_memory_usage",      new utils::VariableValueSlot(rak::mem_fn(torrent::chunk_manager(), &torrent::ChunkManager::max_memory_usage),
                                                                          rak::mem_fn(torrent::chunk_manager(), &torrent::ChunkManager::set_max_memory_usage)));

  variables->insert("safe_sync",             new utils::VariableValueSlot(rak::mem_fn(torrent::chunk_manager(), &torrent::ChunkManager::safe_sync),
                                                                          rak::mem_fn(torrent::chunk_manager(), &torrent::ChunkManager::set_safe_sync)));

  variables->insert("timeout_sync",          new utils::VariableValueSlot(rak::mem_fn(torrent::chunk_manager(), &torrent::ChunkManager::timeout_sync),
                                                                          rak::mem_fn(torrent::chunk_manager(), &torrent::ChunkManager::set_timeout_sync)));

  variables->insert("timeout_safe_sync",     new utils::VariableValueSlot(rak::mem_fn(torrent::chunk_manager(), &torrent::ChunkManager::timeout_safe_sync),
                                                                          rak::mem_fn(torrent::chunk_manager(), &torrent::ChunkManager::set_timeout_safe_sync)));

  variables->insert("preload_type",          new utils::VariableValueSlot(rak::mem_fn(torrent::chunk_manager(), &torrent::ChunkManager::preload_type),
                                                                          rak::mem_fn(torrent::chunk_manager(), &torrent::ChunkManager::set_preload_type)));

  variables->insert("preload_min_size",      new utils::VariableValueSlot(rak::mem_fn(torrent::chunk_manager(), &torrent::ChunkManager::preload_min_size),
                                                                          rak::mem_fn(torrent::chunk_manager(), &torrent::ChunkManager::set_preload_min_size)));

  variables->insert("preload_required_rate", new utils::VariableValueSlot(rak::mem_fn(torrent::chunk_manager(), &torrent::ChunkManager::preload_required_rate),
                                                                          rak::mem_fn(torrent::chunk_manager(), &torrent::ChunkManager::set_preload_required_rate),
                                                                          0, (1 << 10)));

  variables->insert("max_file_size",         new utils::VariableValue(-1));
  variables->insert("split_file_size",       new utils::VariableValue(-1));
  variables->insert("split_suffix",          new utils::VariableAny(".part"));

  variables->insert("port_range",            new utils::VariableStringSlot(NULL, rak::ptr_fn(&apply_port_range)));

  variables->insert("hash_read_ahead",       new utils::VariableValueSlot(rak::ptr_fn(torrent::hash_read_ahead), rak::ptr_fn(&apply_hash_read_ahead)));
  variables->insert("hash_interval",         new utils::VariableValueSlot(rak::ptr_fn(torrent::hash_interval), rak::ptr_fn(&apply_hash_interval)));

  variables->insert("umask",                 new utils::VariableValueSlot(rak::mem_fn(control, &Control::umask), rak::mem_fn(control, &Control::set_umask), 8));
  variables->insert("working_directory",     new utils::VariableStringSlot(rak::mem_fn(control, &Control::working_directory),
                                                                           rak::mem_fn(control, &Control::set_working_directory)));

  variables->insert("load",                  new utils::VariableStringSlot(NULL, rak::ptr_fn(&apply_load)));
  variables->insert("load_verbose",          new utils::VariableStringSlot(NULL, rak::ptr_fn(&apply_load_verbose)));
  variables->insert("load_start",            new utils::VariableStringSlot(NULL, rak::ptr_fn(&apply_load_start)));
  variables->insert("load_start_verbose",    new utils::VariableStringSlot(NULL, rak::ptr_fn(&apply_load_start_verbose)));

  variables->insert("start_tied",            new utils::VariableVoidSlot(rak::ptr_fn(&apply_start_tied)));
  variables->insert("stop_untied",           new utils::VariableVoidSlot(rak::ptr_fn(&apply_stop_untied)));
  variables->insert("close_untied",          new utils::VariableVoidSlot(rak::ptr_fn(&apply_close_untied)));
  variables->insert("remove_untied",         new utils::VariableVoidSlot(rak::ptr_fn(&apply_remove_untied)));

  variables->insert("close_low_diskspace",   new utils::VariableValueSlot(rak::value_fn(int64_t()), rak::ptr_fn(&apply_close_low_diskspace)));
  variables->insert("stop_on_ratio",         new utils::VariableStringSlot(NULL, rak::ptr_fn(&apply_stop_on_ratio)));

  variables->insert("on_insert",             new utils::VariableStringSlot(NULL, rak::bind_ptr_fn(&apply_on_state_change, &control->core()->download_list()->slot_map_insert())));
  variables->insert("on_erase",              new utils::VariableStringSlot(NULL, rak::bind_ptr_fn(&apply_on_state_change, &control->core()->download_list()->slot_map_erase())));
  variables->insert("on_open",               new utils::VariableStringSlot(NULL, rak::bind_ptr_fn(&apply_on_state_change, &control->core()->download_list()->slot_map_open())));
  variables->insert("on_close",              new utils::VariableStringSlot(NULL, rak::bind_ptr_fn(&apply_on_state_change, &control->core()->download_list()->slot_map_close())));
  variables->insert("on_start",              new utils::VariableStringSlot(NULL, rak::bind_ptr_fn(&apply_on_state_change, &control->core()->download_list()->slot_map_start())));
  variables->insert("on_stop",               new utils::VariableStringSlot(NULL, rak::bind_ptr_fn(&apply_on_state_change, &control->core()->download_list()->slot_map_stop())));
  variables->insert("on_hash_queued",        new utils::VariableStringSlot(NULL, rak::bind_ptr_fn(&apply_on_state_change, &control->core()->download_list()->slot_map_hash_queued())));
  variables->insert("on_hash_removed",       new utils::VariableStringSlot(NULL, rak::bind_ptr_fn(&apply_on_state_change, &control->core()->download_list()->slot_map_hash_removed())));
  variables->insert("on_hash_done",          new utils::VariableStringSlot(NULL, rak::bind_ptr_fn(&apply_on_state_change, &control->core()->download_list()->slot_map_hash_done())));
  variables->insert("on_finished",           new utils::VariableStringSlot(NULL, rak::bind_ptr_fn(&apply_on_state_change, &control->core()->download_list()->slot_map_finished())));

  variables->insert("enable_trackers",       new utils::VariableStringSlot(NULL, rak::ptr_fn(&apply_enable_trackers)));
  variables->insert("encoding_list",         new utils::VariableStringSlot(NULL, rak::ptr_fn(&apply_encoding_list)));

  variables->insert("encryption",            new utils::VariableStringSlot(NULL, rak::ptr_fn(&apply_encryption)));
  variables->insert("handshake_log",         new utils::VariableBool(false));
}

template <typename Target, typename GetFunc, typename SetFunc>
utils::Variable*
var_d_value(Target target, GetFunc getFunc, SetFunc setFunc) {
  return new utils::VariableDownloadValueSlot(rak::ftor_fn1(rak::on(std::mem_fun(target), std::mem_fun(getFunc))),
                                              rak::ftor_fn2(rak::on2(std::mem_fun(target), std::mem_fun(setFunc))));
}

template <typename Target, typename GetFunc, typename SetFunc>
utils::Variable*
var_d2_value(Target target, GetFunc getFunc, SetFunc setFunc) {
  return new utils::VariableDownloadValueSlot(rak::ftor_fn1(rak::on(rak::on(std::mem_fun(&core::Download::download), std::mem_fun(target)), std::mem_fun(getFunc))),
                                              rak::ftor_fn2(rak::on2(rak::on(std::mem_fun(&core::Download::download), std::mem_fun(target)), std::mem_fun(setFunc))));
}

template <typename Target, typename GetFunc>
utils::Variable*
var_d2_get_value(Target target, GetFunc getFunc) {
  return new utils::VariableDownloadValueSlot(rak::ftor_fn1(rak::on(rak::on(std::mem_fun(&core::Download::download), std::mem_fun(target)), std::mem_fun(getFunc))), NULL);
}

void
apply_d_create_link(core::Download* download, const std::string& args) {
  rak::split_iterator_t<std::string> itr = rak::split_iterator(args, ',');

  std::string type    = rak::trim(*itr); ++itr;
  std::string prefix  = rak::trim(*itr); ++itr;
  std::string postfix = rak::trim(*itr); ++itr;
  
  if (type.empty())
    throw torrent::input_error("Invalid arguments.");

  std::string target;
  std::string link;

  if (type == "base_path") {
    target = download->get_string("base_path");
    link = rak::path_expand(prefix + download->get_string("base_path") + postfix);

  } else if (type == "base_filename") {
    target = download->get_string("base_path");
    link = rak::path_expand(prefix + download->get_string("base_filename") + postfix);

  } else if (type == "tied") {
    link = rak::path_expand(download->get_string("tied_to_file"));

    if (link.empty())
      return;

    link = rak::path_expand(prefix + link + postfix);
    target = download->get_string("base_path");

  } else {
    throw torrent::input_error("Unknown type argument.");
  }

  if (symlink(target.c_str(), link.c_str()) == -1)
//     control->core()->push_log("create_link failed: " + std::string(rak::error_number::current().c_str()));
//     control->core()->push_log("create_link failed: " + std::string(rak::error_number::current().c_str()) + " to " + target);
    ; // Disabled.
}

void
apply_d_delete_link(core::Download* download, const std::string& args) {
  rak::split_iterator_t<std::string> itr = rak::split_iterator(args, ',');

  std::string type    = rak::trim(*itr); ++itr;
  std::string prefix  = rak::trim(*itr); ++itr;
  std::string postfix = rak::trim(*itr); ++itr;
  
  if (type.empty())
    throw torrent::input_error("Invalid arguments.");

  std::string link;

  if (type == "base_path") {
    link = rak::path_expand(prefix + download->get_string("base_path") + postfix);

  } else if (type == "base_filename") {
    link = rak::path_expand(prefix + download->get_string("base_filename") + postfix);

  } else if (type == "tied") {
    link = rak::path_expand(download->get_string("tied_to_file"));

    if (link.empty())
      return;

    link = rak::path_expand(prefix + link + postfix);

  } else {
    throw torrent::input_error("Unknown type argument.");
  }

  rak::file_stat fileStat;
  rak::error_number::clear_global();

  if (!fileStat.update_link(link) || !fileStat.is_link() ||
      unlink(link.c_str()) == -1)
    ; //     control->core()->push_log("delete_link failed: " + std::string(rak::error_number::current().c_str()));
}

std::string
retrieve_d_base_path(core::Download* download) {
  if (download->file_list()->is_multi_file())
    return download->file_list()->root_dir();
  else
    return download->file_list()->at(0)->frozen_path();
}

std::string
retrieve_d_base_filename(core::Download* download) {
  std::string base;

  if (download->file_list()->is_multi_file())
    base = download->file_list()->root_dir();
  else
    base = download->file_list()->at(0)->frozen_path();

  std::string::size_type split = base.rfind('/');

  if (split == std::string::npos)
    return base;
  else
    return base.substr(split + 1);
}

void
initialize_download_variables() {
  utils::VariableMap* variables = control->download_variables();

  variables->insert("connection_current", new utils::VariableDownloadStringSlot(rak::ftor_fn1(std::mem_fun(&core::Download::connection_current)),
                                                                                rak::ftor_fn2(std::mem_fun(&core::Download::set_connection_current))));

  variables->insert("connection_leech",   new utils::VariableAny(core::Download::connection_type_to_string(torrent::Download::CONNECTION_LEECH)));
  variables->insert("connection_seed",    new utils::VariableAny(core::Download::connection_type_to_string(torrent::Download::CONNECTION_SEED)));

  // 0 - stopped
  // 1 - started
  variables->insert("state",              new utils::VariableObject("rtorrent", "state", torrent::Object::TYPE_VALUE));
  variables->insert("complete",           new utils::VariableObject("rtorrent", "complete", torrent::Object::TYPE_VALUE));

  // 0 - Not hashing
  // 1 - Normal hashing
  // 2 - Download finished, hashing
  variables->insert("hashing",            new utils::VariableObject("rtorrent", "hashing", torrent::Object::TYPE_VALUE));
  variables->insert("tied_to_file",       new utils::VariableObject("rtorrent", "tied_to_file", torrent::Object::TYPE_STRING));

  // The "state_changed" variable is required to be a valid unix time
  // value, it indicates the last time the torrent changed its state,
  // resume/pause.
  variables->insert("state_changed",      new utils::VariableObject("rtorrent", "state_changed", torrent::Object::TYPE_VALUE));

  variables->insert("directory",          new utils::VariableDownloadStringSlot(rak::ftor_fn1(rak::on(std::mem_fun(&core::Download::file_list), std::mem_fun(&torrent::FileList::root_dir))),
                                                                                rak::ftor_fn2(std::mem_fun(&core::Download::set_root_directory))));
  variables->insert("base_path",          new utils::VariableDownloadStringSlot(rak::ptr_fn(&retrieve_d_base_path), NULL));
  variables->insert("base_filename",      new utils::VariableDownloadStringSlot(rak::ptr_fn(&retrieve_d_base_filename), NULL));

  variables->insert("min_peers",          var_d_value(&core::Download::download, &torrent::Download::peers_min, &torrent::Download::set_peers_min));
  variables->insert("max_peers",          var_d_value(&core::Download::download, &torrent::Download::peers_max, &torrent::Download::set_peers_max));
  variables->insert("max_uploads",        var_d_value(&core::Download::download, &torrent::Download::uploads_max, &torrent::Download::set_uploads_max));

  variables->insert("max_file_size",      var_d_value(&core::Download::file_list, &torrent::FileList::max_file_size, &torrent::FileList::set_max_file_size));

  //   variables->insert("split_file_size",    new utils::VariableValueSlot(rak::mem_fn(file_list(), &torrent::FileList::split_file_size),
  //                                                                         rak::mem_fn(file_list(), &torrent::FileList::set_split_file_size)));
  //   variables->insert("split_suffix",       new utils::VariableStringSlot(rak::mem_fn(file_list(), &torrent::FileList::split_suffix),
  //                                                                          rak::mem_fn(file_list(), &torrent::FileList::set_split_suffix)));

  variables->insert("up_rate",            var_d2_get_value(&torrent::Download::mutable_up_rate, &torrent::Rate::rate));
  variables->insert("up_total",           var_d2_get_value(&torrent::Download::mutable_up_rate, &torrent::Rate::total));
  variables->insert("down_rate",          var_d2_get_value(&torrent::Download::mutable_down_rate, &torrent::Rate::rate));
  variables->insert("down_total",         var_d2_get_value(&torrent::Download::mutable_down_rate, &torrent::Rate::total));
  variables->insert("skip_rate",          var_d2_get_value(&torrent::Download::mutable_skip_rate, &torrent::Rate::rate));
  variables->insert("skip_total",         var_d2_get_value(&torrent::Download::mutable_skip_rate, &torrent::Rate::total));

  variables->insert("priority",           new utils::VariableDownloadValueSlot(rak::ftor_fn1(std::mem_fun(&core::Download::priority)), rak::ftor_fn2(std::mem_fun(&core::Download::set_priority))));
  variables->insert("tracker_numwant",    var_d_value(&core::Download::tracker_list, &torrent::TrackerList::numwant, &torrent::TrackerList::set_numwant));

  variables->insert("ignore_commands",    new utils::VariableObject("rtorrent", "ignore_commands", torrent::Object::TYPE_VALUE));

  // Hmm... do we need dupicates?
  variables->insert("print",              new utils::VariableStringSlot(NULL, rak::mem_fn(control->core(), &core::Manager::push_log)));
  variables->insert("create_link",        new utils::VariableDownloadStringSlot(NULL, rak::ptr_fn(&apply_d_create_link)));
  variables->insert("delete_link",        new utils::VariableDownloadStringSlot(NULL, rak::ptr_fn(&apply_d_delete_link)));
}
