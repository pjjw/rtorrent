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

#ifndef RTORRENT_CONTROL_H
#define RTORRENT_CONTROL_H

#include <inttypes.h>
#include <sys/types.h>
#include <rak/timer.h>
#include <rak/priority_queue_default.h>
#include <torrent/torrent.h>

namespace ui {
  class Root;
}

namespace core {
  class Manager;
  class ViewManager;
  class Scheduler;
}

namespace display {
  class Manager;
}

namespace input {
  class InputEvent;
  class Manager;
}  

namespace rpc {
  class FastCgi;
  class SCgi;
  class XmlRpc;
}

namespace utils {
  class VariableMap;
}

class CommandScheduler;

class Control {
public:
  Control();
  ~Control();
  
  bool                is_shutdown_completed()       { return m_shutdownQuick && torrent::is_inactive(); }
  bool                is_shutdown_received()        { return m_shutdownReceived; }
  bool                is_shutdown_started()         { return m_shutdownQuick; }

  void                initialize();
  void                cleanup();

  void                handle_shutdown();

  void                receive_normal_shutdown()     { m_shutdownReceived = true; }
  void                receive_quick_shutdown()      { m_shutdownReceived = true; m_shutdownQuick = true; }

  core::Manager*      core()                        { return m_core; }
  core::ViewManager*  view_manager()                { return m_viewManager; }
  core::Scheduler*    scheduler()                   { return m_scheduler; }

  torrent::Poll*      poll();

  ui::Root*           ui()                          { return m_ui; }
  display::Manager*   display()                     { return m_display; }
  input::Manager*     input()                       { return m_input; }
  input::InputEvent*  input_stdin()                 { return m_inputStdin; }

  CommandScheduler*   command_scheduler()           { return m_commandScheduler; }

  utils::VariableMap* variable()                    { return m_variables; }
  utils::VariableMap* download_variables()          { return m_downloadVariables; }

  rpc::FastCgi*       fast_cgi()                    { return m_fastCgi; }
  void                set_fast_cgi(rpc::FastCgi* f) { m_fastCgi = f; }

  rpc::SCgi*          scgi()                        { return m_scgi; }
  void                set_scgi(rpc::SCgi* f)        { m_scgi = f; }

  rpc::XmlRpc*        xmlrpc()                      { return m_xmlrpc; }
  void                set_xmlrpc(rpc::XmlRpc* f)    { m_xmlrpc = f; }

  uint64_t            tick() const                  { return m_tick; }
  void                inc_tick()                    { m_tick++; }

  mode_t              umask() const                 { return m_umask; }
  void                set_umask(mode_t m);

  const std::string&  working_directory() const     { return m_workingDirectory; }
  void                set_working_directory(const std::string& dir);

private:
  Control(const Control&);
  void operator = (const Control&);

  bool                m_shutdownReceived;
  bool                m_shutdownQuick;

  core::Manager*      m_core;
  core::ViewManager*  m_viewManager;
  core::Scheduler*    m_scheduler;

  ui::Root*           m_ui;
  display::Manager*   m_display;
  input::Manager*     m_input;
  input::InputEvent*  m_inputStdin;

  CommandScheduler*   m_commandScheduler;
  utils::VariableMap* m_variables;
  utils::VariableMap* m_downloadVariables;

  rpc::FastCgi*       m_fastCgi;
  rpc::SCgi*          m_scgi;
  rpc::XmlRpc*        m_xmlrpc;

  uint64_t            m_tick;

  mode_t              m_umask;
  std::string         m_workingDirectory;

  rak::priority_item  m_taskShutdown;
};

#endif
