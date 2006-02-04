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

#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <stdlib.h>
#include <sstream>
#include <sigc++/bind.h>
#include <sigc++/retype_return.h>
#include <torrent/http.h>
#include <torrent/torrent.h>
#include <torrent/exceptions.h>
#include <rak/functional.h>

#ifdef USE_EXECINFO
#include <execinfo.h>
#endif

#include "core/download.h"
#include "core/download_factory.h"
#include "core/manager.h"
#include "display/canvas.h"
#include "display/window.h"
#include "display/manager.h"
#include "input/bindings.h"

#include "utils/directory.h"
#include "utils/variable_map.h"

#include "control.h"
#include "globals.h"
#include "signal_handler.h"
#include "option_file.h"
#include "option_handler_rules.h"
#include "option_parser.h"
#include "command_scheduler.h"
#include "command_scheduler_item.h"

void do_panic(int signum);
void print_help();

int
parse_options(Control* c, utils::VariableMap* optionHandler, int argc, char** argv) {
  try {
    OptionParser optionParser;

    // Converted.
    optionParser.insert_flag('h', sigc::ptr_fun(&print_help));

    optionParser.insert_option('b', sigc::bind<0>(sigc::mem_fun(*optionHandler, &utils::VariableMap::set_string), "bind"));
    optionParser.insert_option('d', sigc::bind<0>(sigc::mem_fun(*optionHandler, &utils::VariableMap::set_string), "directory"));
    optionParser.insert_option('i', sigc::bind<0>(sigc::mem_fun(*optionHandler, &utils::VariableMap::set_string), "ip"));
    optionParser.insert_option('p', sigc::bind<0>(sigc::mem_fun(*optionHandler, &utils::VariableMap::set_string), "port_range"));
    optionParser.insert_option('s', sigc::bind<0>(sigc::mem_fun(*optionHandler, &utils::VariableMap::set_string), "session"));

    optionParser.insert_option_list('o', sigc::mem_fun(*optionHandler, &utils::VariableMap::set_string));

    return optionParser.process(argc, argv);

  } catch (torrent::input_error& e) {
    throw std::runtime_error("Failed to parse command line option: " + std::string(e.what()));
  }
}

void
load_session_torrents(Control* c) {
  // Load session torrents.
  std::list<std::string> l = c->core()->download_store().get_formated_entries().make_list();

  for (std::list<std::string>::iterator first = l.begin(), last = l.end(); first != last; ++first) {
    core::DownloadFactory* f = new core::DownloadFactory(*first, c->core());

    // Replace with session torrent flag.
    f->set_session(true);
    f->slot_finished(sigc::bind(sigc::ptr_fun(&rak::call_delete_func<core::DownloadFactory>), f));
    f->load();
    f->commit();
  }
}

void
load_arg_torrents(Control* c, char** first, char** last) {
  //std::for_each(begin, end, std::bind1st(std::mem_fun(&core::Manager::insert), &c->get_core()));
  for (; first != last; ++first) {
    core::DownloadFactory* f = new core::DownloadFactory(*first, c->core());

    // Replace with session torrent flag.
    f->set_start(true);
    f->slot_finished(sigc::bind(sigc::ptr_fun(&rak::call_delete_func<core::DownloadFactory>), f));
    f->load();
    f->commit();
  }
}

rak::timer
client_next_timeout() {
  if (taskScheduler.empty())
    return 60 * 1000000;
  else if (taskScheduler.top()->time() <= cachedTime)
    return 0;
  else
    return taskScheduler.top()->time() - cachedTime;
}

int
main(int argc, char** argv) {
  try {

    // Temporary.
    //setlocale(LC_ALL, "");

    cachedTime = rak::timer::current();

    control = new Control;
    
    srandom(cachedTime.usec());
    srand48(cachedTime.usec());

    initialize_option_handler(control);

    SignalHandler::set_ignore(SIGPIPE);
    SignalHandler::set_handler(SIGINT,   sigc::mem_fun(control, &Control::receive_normal_shutdown));
    SignalHandler::set_handler(SIGTERM,  sigc::mem_fun(control, &Control::receive_quick_shutdown));
    SignalHandler::set_handler(SIGWINCH, sigc::mem_fun(control->display(), &display::Manager::force_redraw));
    SignalHandler::set_handler(SIGSEGV,  sigc::bind(sigc::ptr_fun(&do_panic), SIGSEGV));
    SignalHandler::set_handler(SIGBUS,   sigc::bind(sigc::ptr_fun(&do_panic), SIGBUS));
    SignalHandler::set_handler(SIGFPE,   sigc::bind(sigc::ptr_fun(&do_panic), SIGFPE));

    control->core()->initialize_first();

    OptionFile optionFile;
    optionFile.slot_option(sigc::mem_fun(control->variables(), &utils::VariableMap::process_command));

    if (getenv("HOME") && !optionFile.process_file(getenv("HOME") + std::string("/.rtorrent.rc")))
      control->core()->get_log_important().push_front("Could not load \"~/.rtorrent.rc\".");

    int firstArg = parse_options(control, control->variables(), argc, argv);

    control->initialize();

    // Load session torrents and perform scheduled tasks to ensure
    // session torrents are loaded before arg torrents.
    load_session_torrents(control);
    rak::priority_queue_perform(&taskScheduler, cachedTime);

    load_arg_torrents(control, argv + firstArg, argv + argc);

    control->display()->adjust_layout();

    while (!control->is_shutdown_completed()) {
      if (control->is_shutdown_received())
	control->handle_shutdown();

      control->inc_tick();

      cachedTime = rak::timer::current();
      rak::priority_queue_perform(&taskScheduler, cachedTime);

      // Do shutdown check before poll, not after.
      control->core()->get_poll_manager()->poll(client_next_timeout());
    }

    control->cleanup();

  } catch (torrent::base_error& e) {
    display::Canvas::cleanup();
    delete control;

    std::cout << "Caught exception: " << e.what() << std::endl;
    return -1;

  } catch (std::exception& e) {
    display::Canvas::cleanup();
    delete control;

    std::cout << e.what() << std::endl;
    return -1;
  }

  delete control;

  return 0;
}

void
do_panic(int signum) {
  // Use the default signal handler in the future to avoid infinit
  // loops.
  SignalHandler::set_default(signum);
  display::Canvas::cleanup();

  std::cout << "Caught " << SignalHandler::as_string(signum) << ", dumping stack:" << std::endl;
  
#ifdef USE_EXECINFO
  void* stackPtrs[20];

  // Print the stack and exit.
  int stackSize = backtrace(stackPtrs, 20);
  char** stackStrings = backtrace_symbols(stackPtrs, stackSize);

  for (int i = 0; i < stackSize; ++i)
    std::cout << i << ' ' << stackStrings[i] << std::endl;

#else
  std::cout << "Stack dump not enabled." << std::endl;
#endif
  
  if (signum == SIGBUS)
    std::cout << "A bus error propably means you ran out of diskspace." << std::endl;

  exit(-1);
}

void
print_help() {
  std::cout << "Rakshasa's BitTorrent client version " VERSION "." << std::endl;
  std::cout << std::endl;
  std::cout << "All value pairs (f.ex rate and queue size) will be in the UP/DOWN" << std::endl;
  std::cout << "order. Use the up/down/left/right arrow keys to move between screens." << std::endl;
  std::cout << std::endl;
  std::cout << "Usage: rtorrent [OPTIONS]... [FILE]... [URL]..." << std::endl;
  std::cout << "  -h                Display this very helpful text" << std::endl;
  std::cout << "  -b <a.b.c.d>      Bind the listening socket to this IP" << std::endl;
  std::cout << "  -i <a.b.c.d>      Change the IP that is sent to the tracker" << std::endl;
  std::cout << "  -p <int>-<int>    Set port range for incoming connections" << std::endl;
  std::cout << "  -d <directory>    Save torrents to this directory by default" << std::endl;
  std::cout << "  -s <directory>    Set the session directory" << std::endl;
  std::cout << "  -o key=opt,...    Set options, see 'rtorrent.rc' file" << std::endl;
  std::cout << std::endl;
  std::cout << "Main view keys:" << std::endl;
  std::cout << "  backspace         Add a torrent url or path" << std::endl;
  std::cout << "  ^s                Start torrent" << std::endl;
  std::cout << "  ^d                Stop torrent or delete a stopped torrent" << std::endl;
  std::cout << "  ^r                Manually initiate hash checking" << std::endl;
  std::cout << "  ^q                Initiate shutdown or skip shutdown process" << std::endl;
  std::cout << "  a,s,d,z,x,c       Adjust upload throttle" << std::endl;
  std::cout << "  A,S,D,Z,X,C       Adjust download throttle" << std::endl;
  std::cout << "  right             View torrent" << std::endl;
  std::cout << std::endl;
  std::cout << "Download view keys:" << std::endl;
  std::cout << "  spacebar          Depends on the current view" << std::endl;
  std::cout << "  1,2               Adjust max uploads" << std::endl;
  std::cout << "  3,4,5,6           Adjust min/max connected peers" << std::endl;
  std::cout << "  t/T               Query tracker for more peers / Force query" << std::endl;
  std::cout << "  *                 Snub peer" << std::endl;
  std::cout << "  right             View files" << std::endl;
  std::cout << "  p                 View peer information" << std::endl;
  std::cout << "  o                 View trackers" << std::endl;
  std::cout << std::endl;

  std::cout << "Report bugs to <jaris@ifi.uio.no>." << std::endl;

  exit(0);
}
