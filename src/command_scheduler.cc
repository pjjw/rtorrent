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

#include "core/manager.h"
#include "core/download_list.h"
#include "rpc/command_variable.h"

#include "globals.h"
#include "control.h"
#include "command_helpers.h"

torrent::Object
cmd_scheduler_simple_added(core::Download* download, const torrent::Object& rawArgs) {
  control->core()->download_list()->resume(download);

  return torrent::Object();
}

torrent::Object
cmd_scheduler_simple_removed(core::Download* download, const torrent::Object& rawArgs) {
  control->core()->download_list()->pause(download);

  return torrent::Object();
}

void
initialize_command_scheduler() {
//   core::DownloadList* dList = control->core()->download_list();

//   CMD_G("scheduler.active", rak::bind_ptr_fn(&cmd_call, "view.size=active"));

  CMD_V("scheduler.", "max_active", value, (int64_t)-1);

  CMD_D_ANY("scheduler.simple.added",   rak::ptr_fn(&cmd_scheduler_simple_added));
  CMD_D_ANY("scheduler.simple.removed", rak::ptr_fn(&cmd_scheduler_simple_removed));
}
