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

#include <unistd.h>

#include "core/manager.h"
#include "display/canvas.h"
#include "display/window.h"
#include "display/manager.h"
#include "input/manager.h"
#include "input/input_event.h"
#include "ui/root.h"
#include "utils/variable_map.h"

#include "command_scheduler.h"

#include "control.h"

Control::Control() :
  m_shutdownReceived(false),

  m_ui(new ui::Root()),
  m_core(new core::Manager()),
  m_display(new display::Manager()),
  m_input(new input::Manager()),
  m_inputStdin(new input::InputEvent(STDIN_FILENO)),

  m_commandScheduler(new CommandScheduler()),
  m_variables(new utils::VariableMap()),

  m_tick(0) {

  m_inputStdin->slot_pressed(sigc::mem_fun(m_input, &input::Manager::pressed));

  m_taskShutdown.set_slot(rak::mem_fn(this, &Control::receive_shutdown));

  m_commandScheduler->set_slot_command(rak::mem_fn(m_variables, &utils::VariableMap::process_command));
  m_commandScheduler->set_slot_error_message(rak::mem_fn(m_core, &core::Manager::push_log));
}

Control::~Control() {
  delete m_inputStdin;
  delete m_input;

  delete m_commandScheduler;
  delete m_variables;

  delete m_ui;
  delete m_display;
  delete m_core;
}

void
Control::initialize() {
  display::Canvas::initialize();
  display::Window::slot_schedule(rak::make_mem_fun(m_display, &display::Manager::schedule));
  display::Window::slot_unschedule(rak::make_mem_fun(m_display, &display::Manager::unschedule));
  display::Window::slot_adjust(rak::make_mem_fun(m_display, &display::Manager::adjust_layout));

  m_core->get_poll_manager()->signal_interrupted().connect(sigc::mem_fun(*m_inputStdin, &input::InputEvent::event_read));
  m_core->get_poll_manager()->signal_interrupted().connect(sigc::ptr_fun(display::Canvas::do_update));
  m_core->get_poll_manager()->get_http_stack()->set_user_agent(std::string(PACKAGE "/" VERSION "/") + torrent::version());

  m_core->initialize_second();
  m_core->listen_open();

  m_ui->init(this);

  m_inputStdin->insert(m_core->get_poll_manager()->get_torrent_poll());
}

void
Control::cleanup() {
  priority_queue_erase(&taskScheduler, &m_taskShutdown);

  m_inputStdin->remove(m_core->get_poll_manager()->get_torrent_poll());

  m_ui->cleanup();
  m_core->cleanup();
  
  display::Canvas::erase_std();
  display::Canvas::refresh_std();
  display::Canvas::do_update();
  display::Canvas::cleanup();
}

// I think it should be safe to initiate the shutdown from anywhere,
// but if it isn't, use a delay task.
void
Control::receive_shutdown() {
  if (!m_shutdownReceived) {
    torrent::listen_close();
    
    m_core->shutdown(false);
    m_shutdownReceived = true;

    if (!m_taskShutdown.is_queued())
      priority_queue_insert(&taskScheduler, &m_taskShutdown, cachedTime + 5 * 1000000);

  } else {
    m_core->shutdown(true);
  }
}
