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

#include <functional>
#include <rak/address_info.h>
#include <rak/path.h>
#include <torrent/connection_manager.h>
#include <torrent/dht_manager.h>
#include <torrent/throttle.h>
#include <torrent/tracker.h>
#include <torrent/tracker_list.h>
#include <torrent/torrent.h>
#include <torrent/rate.h>

#include "core/dht_manager.h"
#include "core/download.h"
#include "core/manager.h"
#include "rpc/scgi.h"
#include "ui/root.h"
#include "rpc/command_slot.h"
#include "rpc/command_variable.h"
#include "rpc/parse.h"
#include "rpc/parse_commands.h"

#include "globals.h"
#include "control.h"
#include "command_helpers.h"

torrent::Object
apply_encryption(const torrent::Object& rawArgs) {
  const torrent::Object::list_type& args = rawArgs.as_list();

  uint32_t options_mask = torrent::ConnectionManager::encryption_none;

  for (torrent::Object::list_const_iterator itr = args.begin(), last = args.end(); itr != last; itr++) {
    const std::string& opt = itr->as_string();

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
      throw torrent::input_error("Invalid encryption option.");
  }

  torrent::connection_manager()->set_encryption_options(options_mask);

  return torrent::Object();
}

torrent::Object
apply_tos(const torrent::Object& rawArg) {
  rpc::Command::value_type value;
  torrent::ConnectionManager* cm = torrent::connection_manager();

  const std::string& arg = rawArg.as_string();

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
  else if (!rpc::parse_whole_value_nothrow(arg.c_str(), &value, 16, 1))
    throw torrent::input_error("Invalid TOS identifier.");

  cm->set_priority(value);

  return torrent::Object();
}

void apply_hash_read_ahead(int arg)              { torrent::set_hash_read_ahead(arg << 20); }
void apply_hash_interval(int arg)                { torrent::set_hash_interval(arg * 1000); }
void apply_encoding_list(const std::string& arg) { torrent::encoding_list()->push_back(arg); }

struct call_add_node_t {
  call_add_node_t(int port) : m_port(port) { }

  void operator() (const sockaddr* sa, int err) {
    if (sa == NULL)
      control->core()->push_log("Could not resolve host.");
    else
      torrent::dht_manager()->add_node(sa, m_port);
  }

  int m_port;
};

void
apply_dht_add_node(const std::string& arg) {
  if (!torrent::dht_manager()->is_valid())
    throw torrent::input_error("DHT not enabled.");

  int port, ret;
  char dummy;
  char host[1024];

  ret = std::sscanf(arg.c_str(), "%1023[^:]:%i%c", host, &port, &dummy);

  if (ret == 1)
    port = 6881;
  else if (ret != 2)
    throw torrent::input_error("Could not parse host.");

  if (port < 1 || port > 65535)
    throw torrent::input_error("Invalid port number.");

  torrent::connection_manager()->resolver()(host, (int)rak::socket_address::pf_inet, SOCK_DGRAM, call_add_node_t(port));
}

void
apply_enable_trackers(int64_t arg) {
  for (core::Manager::DListItr itr = control->core()->download_list()->begin(), last = control->core()->download_list()->end(); itr != last; ++itr) {
    std::for_each((*itr)->tracker_list()->begin(), (*itr)->tracker_list()->end(),
                  arg ? std::mem_fun(&torrent::Tracker::enable) : std::mem_fun(&torrent::Tracker::disable));

    if (arg && !rpc::call_command_value("get_use_udp_trackers"))
      (*itr)->enable_udp_trackers(false);
  }    
}

torrent::File*
xmlrpc_find_file(core::Download* download, uint32_t index) {
  if (index >= download->file_list()->size_files())
    return NULL;

  return (*download->file_list())[index];
}

// Ergh... time to update the Tracker API to allow proper ptrs.
torrent::Tracker*
xmlrpc_find_tracker(core::Download* download, uint32_t index) {
  if (index >= download->tracker_list()->size())
    return NULL;

  return download->tracker_list()->at(index);
}

void
initialize_xmlrpc() {
  rpc::xmlrpc.initialize();
  rpc::xmlrpc.set_slot_find_download(rak::mem_fn(control->core()->download_list(), &core::DownloadList::find_hex_ptr));
  rpc::xmlrpc.set_slot_find_file(rak::ptr_fn(&xmlrpc_find_file));
  rpc::xmlrpc.set_slot_find_tracker(rak::ptr_fn(&xmlrpc_find_tracker));

  unsigned int count = 0;

  for (rpc::CommandMap::const_iterator itr = rpc::commands.begin(), last = rpc::commands.end(); itr != last; itr++, count++) {
    if (!(itr->second.m_flags & rpc::CommandMap::flag_public_xmlrpc))
      continue;

    rpc::xmlrpc.insert_command(itr->first, itr->second.m_parm, itr->second.m_doc);
  }

  char buffer[128];
  sprintf(buffer, "XMLRPC initialized with %u functions.", count);

  control->core()->push_log(buffer);
}

void
apply_scgi(const std::string& arg, int type) {
  if (control->scgi() != NULL)
    throw torrent::input_error("SCGI already enabled.");

  if (!rpc::xmlrpc.is_valid())
    initialize_xmlrpc();

  // Fix this...
  control->set_scgi(new rpc::SCgi);

  rak::address_info* ai = NULL;
  rak::socket_address sa;
  rak::socket_address* saPtr;

  try {
    int port, err;
    char dummy;
    char address[1024];

    switch (type) {
    case 1:
      if (std::sscanf(arg.c_str(), ":%i%c", &port, &dummy) == 1) {
        sa.sa_inet()->clear();
        saPtr = &sa;

        control->core()->push_log("The SCGI socket has not been bound to any address and likely poses a security risk.");

      } else if (std::sscanf(arg.c_str(), "%1023[^:]:%i%c", address, &port, &dummy) == 2) {
        if ((err = rak::address_info::get_address_info(address, PF_INET, SOCK_STREAM, &ai)) != 0)
          throw torrent::input_error("Could not bind address: " + std::string(rak::address_info::strerror(err)) + ".");

        saPtr = ai->address();

        control->core()->push_log("The SCGI socket is bound to a specific network device yet may still pose a security risk, consider using 'scgi_local'.");

      } else {
        throw torrent::input_error("Could not parse address.");
      }

      if (port <= 0 || port >= (1 << 16))
        throw torrent::input_error("Invalid port number.");

      saPtr->set_port(port);
      control->scgi()->open_port(saPtr, saPtr->length(), rpc::call_command_value("get_scgi_dont_route"));

      break;

    case 2:
    default:
      control->scgi()->open_named(rak::path_expand(arg));
      break;
    }

    rak::address_info::free_address_info(ai);

  } catch (torrent::local_error& e) {
    rak::address_info::free_address_info(ai);

    throw torrent::input_error(e.what());
  }

  control->scgi()->set_slot_process(rak::mem_fn(&rpc::xmlrpc, &rpc::XmlRpc::process));
}

void
apply_xmlrpc_dialect(const std::string& arg) {
  int value;

  if (arg == "i8")
    value = rpc::XmlRpc::dialect_i8;
  else if (arg == "apache")
    value = rpc::XmlRpc::dialect_apache;
  else if (arg == "generic")
    value = rpc::XmlRpc::dialect_generic;
  else
    value = -1;

  rpc::xmlrpc.set_dialect(value);
}

void
initialize_command_network() {
  torrent::ConnectionManager* cm = torrent::connection_manager();
  core::CurlStack* httpStack = control->core()->get_poll_manager()->get_http_stack();

  ADD_VARIABLE_BOOL("use_udp_trackers", true);

  // Isn't port_open used?
  ADD_VARIABLE_BOOL("port_open", true);
  ADD_VARIABLE_BOOL("port_random", true);
  ADD_VARIABLE_STRING("port_range", "6881-6999");

  ADD_VARIABLE_STRING("connection_leech", "leech");
  ADD_VARIABLE_STRING("connection_seed", "seed");

  ADD_VARIABLE_VALUE("min_peers", 40);
  ADD_VARIABLE_VALUE("max_peers", 100);
  ADD_VARIABLE_VALUE("min_peers_seed", -1);
  ADD_VARIABLE_VALUE("max_peers_seed", -1);

  ADD_VARIABLE_VALUE("max_uploads", 15);

  ADD_VARIABLE_VALUE("max_uploads_div",      1);
  ADD_VARIABLE_VALUE("max_uploads_global",   0);
  ADD_VARIABLE_VALUE("max_downloads_div",    1);
  ADD_VARIABLE_VALUE("max_downloads_global", 0);

//   ADD_COMMAND_VALUE_TRI("max_uploads_global",   rak::make_mem_fun(control->ui(), &ui::Root::set_max_uploads_global), rak::make_mem_fun(control->ui(), &ui::Root::max_uploads_global));
//   ADD_COMMAND_VALUE_TRI("max_downloads_global", rak::make_mem_fun(control->ui(), &ui::Root::set_max_downloads_global), rak::make_mem_fun(control->ui(), &ui::Root::max_downloads_global));

  ADD_COMMAND_VALUE_TRI_KB("download_rate",     rak::make_mem_fun(control->ui(), &ui::Root::set_down_throttle_i64), rak::make_mem_fun(torrent::down_throttle_global(), &torrent::Throttle::max_rate));
  ADD_COMMAND_VALUE_TRI_KB("upload_rate",       rak::make_mem_fun(control->ui(), &ui::Root::set_up_throttle_i64), rak::make_mem_fun(torrent::up_throttle_global(), &torrent::Throttle::max_rate));

  ADD_COMMAND_VOID("get_up_rate",               rak::make_mem_fun(torrent::up_rate(), &torrent::Rate::rate));
  ADD_COMMAND_VOID("get_up_total",              rak::make_mem_fun(torrent::up_rate(), &torrent::Rate::total));
  ADD_COMMAND_VOID("get_down_rate",             rak::make_mem_fun(torrent::down_rate(), &torrent::Rate::rate));
  ADD_COMMAND_VOID("get_down_total",            rak::make_mem_fun(torrent::down_rate(), &torrent::Rate::total));

  ADD_VARIABLE_VALUE("tracker_numwant", -1);

  ADD_COMMAND_LIST("encryption",          rak::ptr_fn(&apply_encryption));

  ADD_COMMAND_STRING("tos",               rak::ptr_fn(&apply_tos));

  ADD_COMMAND_STRING_TRI("bind",          rak::make_mem_fun(control->core(), &core::Manager::set_bind_address), rak::make_mem_fun(control->core(), &core::Manager::bind_address));
  ADD_COMMAND_STRING_TRI("ip",            rak::make_mem_fun(control->core(), &core::Manager::set_local_address), rak::make_mem_fun(control->core(), &core::Manager::local_address));
  ADD_COMMAND_STRING_TRI("proxy_address", rak::make_mem_fun(control->core(), &core::Manager::set_proxy_address), rak::make_mem_fun(control->core(), &core::Manager::proxy_address));
  ADD_COMMAND_STRING_TRI("http_proxy",    rak::make_mem_fun(httpStack, &core::CurlStack::set_http_proxy), rak::make_mem_fun(httpStack, &core::CurlStack::http_proxy));
  ADD_COMMAND_STRING_TRI("http_capath",   rak::make_mem_fun(httpStack, &core::CurlStack::set_http_capath), rak::make_mem_fun(httpStack, &core::CurlStack::http_capath));
  ADD_COMMAND_STRING_TRI("http_cacert",   rak::make_mem_fun(httpStack, &core::CurlStack::set_http_cacert), rak::make_mem_fun(httpStack, &core::CurlStack::http_cacert));

  ADD_COMMAND_VALUE_TRI("send_buffer_size",    rak::make_mem_fun(cm, &torrent::ConnectionManager::set_send_buffer_size), rak::make_mem_fun(cm, &torrent::ConnectionManager::send_buffer_size));
  ADD_COMMAND_VALUE_TRI("receive_buffer_size", rak::make_mem_fun(cm, &torrent::ConnectionManager::set_receive_buffer_size), rak::make_mem_fun(cm, &torrent::ConnectionManager::receive_buffer_size));

  ADD_COMMAND_VALUE_TRI("hash_max_tries",       std::ptr_fun(&torrent::set_hash_max_tries), rak::ptr_fun(&torrent::hash_max_tries));
  ADD_COMMAND_VALUE_TRI("max_open_files",       std::ptr_fun(&torrent::set_max_open_files), rak::ptr_fun(&torrent::max_open_files));
  ADD_COMMAND_VALUE_TRI("max_open_sockets",     rak::make_mem_fun(cm, &torrent::ConnectionManager::set_max_size), rak::make_mem_fun(cm, &torrent::ConnectionManager::max_size));
  ADD_COMMAND_VALUE_TRI("max_open_http",        rak::make_mem_fun(httpStack, &core::CurlStack::set_max_active), rak::make_mem_fun(httpStack, &core::CurlStack::max_active));

  ADD_COMMAND_STRING_UN("scgi_port",            rak::bind2nd(std::ptr_fun(&apply_scgi), 1));
  ADD_COMMAND_STRING_UN("scgi_local",           rak::bind2nd(std::ptr_fun(&apply_scgi), 2));
  ADD_VARIABLE_BOOL    ("scgi_dont_route", false);
  ADD_COMMAND_STRING_UN("xmlrpc_dialect",       std::ptr_fun(&apply_xmlrpc_dialect));
  ADD_COMMAND_VALUE_TRI("xmlrpc_size_limit",    std::ptr_fun(&rpc::XmlRpc::set_size_limit), rak::ptr_fun(&rpc::XmlRpc::size_limit));

  ADD_COMMAND_VALUE_TRI("hash_read_ahead",      std::ptr_fun(&apply_hash_read_ahead), rak::ptr_fun(torrent::hash_read_ahead));
  ADD_COMMAND_VALUE_TRI("hash_interval",        std::ptr_fun(&apply_hash_interval), rak::ptr_fun(torrent::hash_interval));

  ADD_COMMAND_VALUE_UN("enable_trackers",       std::ptr_fun(&apply_enable_trackers));
  ADD_COMMAND_STRING_UN("encoding_list",        std::ptr_fun(&apply_encoding_list));

  ADD_VARIABLE_VALUE("dht_port", 6881);
  ADD_COMMAND_STRING_UN("dht",                  rak::make_mem_fun(control->dht_manager(), &core::DhtManager::set_start));
  ADD_COMMAND_STRING_UN("dht_add_node",         std::ptr_fun(&apply_dht_add_node));
  ADD_COMMAND_VOID("dht_statistics",            rak::make_mem_fun(control->dht_manager(), &core::DhtManager::dht_statistics));

  ADD_VARIABLE_BOOL("peer_exchange", true);

  // Not really network stuff:
  ADD_VARIABLE_BOOL("handshake_log", false);
  ADD_VARIABLE_STRING("tracker_dump", "");
}
