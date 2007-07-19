// rTorrent - BitTorrent client
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

//#include <functional>
//#include <rak/file_stat.h>
#include <rak/error_number.h>
#include <rak/path.h>
//#include <torrent/rate.h>
#include <torrent/data/file.h>
#include <torrent/data/file_list.h>

//#include "core/download.h"
#include "core/manager.h"
#include "rpc/command_slot.h"
#include "rpc/command_file_slot.h"

#include "globals.h"
#include "control.h"
#include "command_helpers.h"


#define ADD_CF_SLOT(key, function, slot, parm, doc)    \
  commandFileSlotsItr->set_slot(slot); \
  rpc::commands.insert_file(key, commandFileSlotsItr++, &rpc::CommandFileSlot::function, rpc::CommandMap::flag_dont_delete, parm, doc);

#define ADD_CF_SLOT_PUBLIC(key, function, slot, parm, doc)    \
  commandFileSlotsItr->set_slot(slot); \
  rpc::commands.insert_file(key, commandFileSlotsItr++, &rpc::CommandFileSlot::function, rpc::CommandMap::flag_dont_delete | rpc::CommandMap::flag_public_xmlrpc, parm, doc);

/*
#define ADD_CF_VOID(key, slot) \
  ADD_CF_SLOT_PUBLIC("get_f_" key, call_unknown, rpc::object_f_fn(slot), "i:", "")

#define ADD_CF_V_VOID(key, slot) \
  ADD_CF_SLOT_PUBLIC("d_" key, call_unknown, rpc::object_f_fn(slot), "i:", "")

#define ADD_CF_F_VOID(key, slot) \
  ADD_CF_SLOT_PUBLIC("d_" key, call_unknown, rpc::object_void_f_fn(slot), "i:", "")

#define ADD_CF_LIST(key, slot) \
  ADD_CF_SLOT_PUBLIC(key, call_list, slot, "i:", "")

#define ADD_CF_VARIABLE_VALUE(key, firstKey, secondKey) \
  ADD_CF_SLOT_PUBLIC("get_f_" key, call_unknown, rpc::get_variable_f_fn(firstKey, secondKey), "i:", ""); \
  ADD_CF_SLOT("set_f_" key, call_value,   rpc::set_variable_f_fn(firstKey, secondKey), "i:i", "");

#define ADD_CF_VARIABLE_VALUE_PUBLIC(key, firstKey, secondKey) \
  ADD_CF_SLOT_PUBLIC("get_f_" key, call_unknown, rpc::get_variable_f_fn(firstKey, secondKey), "i:", ""); \
  ADD_CF_SLOT_PUBLIC("set_f_" key, call_value,   rpc::set_variable_f_fn(firstKey, secondKey), "i:i", "");

#define ADD_CF_VARIABLE_STRING(key, firstKey, secondKey) \
  ADD_CF_SLOT_PUBLIC("get_f_" key, call_unknown, rpc::get_variable_f_fn(firstKey, secondKey), "i:", ""); \
  ADD_CF_SLOT("set_f_" key, call_string,  rpc::set_variable_f_fn(firstKey, secondKey), "i:s", "");

*/
#define ADD_CF_VALUE_UNI(key, get) \
  ADD_CF_SLOT_PUBLIC("get_f_" key, call_unknown, rpc::object_void_f_fn(get), "i:", "")

/*
#define ADD_CF_VALUE_BI(key, set, get) \
  ADD_CF_SLOT_PUBLIC("set_f_" key, call_value, rpc::object_value_f_fn(set), "i:i", "") \
  ADD_CF_SLOT_PUBLIC("get_f_" key, call_unknown, rpc::object_void_f_fn(get), "i:", "")

#define ADD_CF_VALUE_MEM_BI(key, target, set, get) \
  ADD_CF_VALUE_BI(key, rak::on2(std::mem_fun(target), std::mem_fun(set)), rak::on(std::mem_fun(target), std::mem_fun(get)));

*/
#define ADD_CF_STRING_UNI(key, get) \
  ADD_CF_SLOT_PUBLIC("get_f_" key, call_unknown, rpc::object_void_f_fn(get), "s:", "")

/*
#define ADD_CF_STRING_BI(key, set, get) \
  ADD_CF_SLOT_PUBLIC("set_f_" key, call_string, rpc::object_string_f_fn(set), "i:s", "") \
  ADD_CF_SLOT_PUBLIC("get_f_" key, call_unknown, rpc::object_void_f_fn(get), "s:", "")
*/

void
initialize_command_file() {
  ADD_CF_VALUE_UNI("is_created", std::mem_fun(&torrent::File::is_created));
  ADD_CF_VALUE_UNI("is_open", std::mem_fun(&torrent::File::is_open));

  ADD_CF_VALUE_UNI("size_bytes", std::mem_fun(&torrent::File::size_bytes));
  ADD_CF_VALUE_UNI("size_chunks", std::mem_fun(&torrent::File::size_chunks));
  ADD_CF_VALUE_UNI("completed_chunks", std::mem_fun(&torrent::File::completed_chunks));

  ADD_CF_VALUE_UNI("offset",           std::mem_fun(&torrent::File::offset));
  ADD_CF_VALUE_UNI("range_first", std::mem_fun(&torrent::File::range_first));
  ADD_CF_VALUE_UNI("range_second", std::mem_fun(&torrent::File::range_second));

  // Priority needs to be protected...
  ADD_CF_VALUE_UNI("priority", std::mem_fun(&torrent::File::priority));

  ADD_CF_STRING_UNI("frozen_path", std::mem_fun(&torrent::File::frozen_path));
  ADD_CF_VALUE_UNI("match_depth_prev", std::mem_fun(&torrent::File::match_depth_prev));
  ADD_CF_VALUE_UNI("match_depth_next", std::mem_fun(&torrent::File::match_depth_next));

  ADD_CF_VALUE_UNI("last_touched", std::mem_fun(&torrent::File::last_touched));
}
