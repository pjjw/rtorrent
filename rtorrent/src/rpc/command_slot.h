// rTorrent - BitTorrent client
// Copyright (C) 2006, Jari Sundell
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

#ifndef RTORRENT_RPC_COMMAND_SLOT_H
#define RTORRENT_RPC_COMMAND_SLOT_H

#include <functional>
#include <limits>
#include <inttypes.h>
#include <torrent/object.h>
#include <rak/functional_fun.h>

#include "command.h"

namespace rpc {

class CommandSlot : public Command {
public:
  typedef rak::function1<torrent::Object, const torrent::Object&> slot_type;

//   template <typename SlotSet>
//   CommandSlot(SlotSet* slotSet) {
//     m_slotSet.set(slotSet);
//   }
  
  CommandSlot() {}

  CommandSlot(slot_type::base_type* s) {
    m_slot.set(s);
  }

  void                set_slot(slot_type::base_type* s) { m_slot.set(s); }

  static const torrent::Object call_unknown(Command* rawCommand, const torrent::Object& args);

  static const torrent::Object call_list(Command* rawCommand, const torrent::Object& args);
  static const torrent::Object call_string(Command* rawCommand, const torrent::Object& args);

  static const torrent::Object call_value_base(Command* rawCommand, const torrent::Object& args, int base, int unit);

  static const torrent::Object call_value(Command* rawCommand, const torrent::Object& args)     { return call_value_base(rawCommand, args, 0, 1); }
  static const torrent::Object call_value_kb(Command* rawCommand, const torrent::Object& args)  { return call_value_base(rawCommand, args, 0, 1 << 10); }
  static const torrent::Object call_value_oct(Command* rawCommand, const torrent::Object& args) { return call_value_base(rawCommand, args, 8, 1); }

  template <int base, int unit>
  static const torrent::Object call_value(Command* rawCommand, const torrent::Object& args)  { return call_value_base(rawCommand, args, base, unit); }

//   static const torrent::Object& get_list(Command* rawCommand, const torrent::Object& args);

private:
  slot_type           m_slot;
};

// Some slots that convert torrent::Object arguments to proper
// function calls.

template <typename Func, typename Result = typename Func::result_type>
class object_void_fn_t : public rak::function_base1<torrent::Object, const torrent::Object&> {
public:
  object_void_fn_t(Func func) : m_func(func) {}
  
  virtual torrent::Object operator () (const torrent::Object& arg1) { return torrent::Object(m_func()); }

private:
  Func m_func;
};

template <typename Func>
class object_void_fn_t<Func, void> : public rak::function_base1<torrent::Object, const torrent::Object&> {
public:
  object_void_fn_t(Func func) : m_func(func) {}
  
  virtual torrent::Object operator () (const torrent::Object& arg1) {
    m_func();
    return torrent::Object();
  }

private:
  Func m_func;
};

template <typename Func, typename Result = typename Func::result_type>
class object_value_fn1_t : public rak::function_base1<torrent::Object, const torrent::Object&> {
public:
  object_value_fn1_t(Func func) : m_func(func) {}
  
  virtual torrent::Object operator () (const torrent::Object& arg1) { return torrent::Object((int64_t)m_func(arg1.as_value())); }

private:
  Func m_func;
};

template <typename Func>
class object_value_fn1_t<Func, void> : public rak::function_base1<torrent::Object, const torrent::Object&> {
public:
  object_value_fn1_t(Func func) : m_func(func) {}
  
  virtual torrent::Object operator () (const torrent::Object& arg1) {
    m_func(arg1.as_value());

    return torrent::Object();
  }

private:
  Func m_func;
};

template <typename Func, typename Result = typename Func::result_type>
class object_string_fn1_t : public rak::function_base1<torrent::Object, const torrent::Object&> {
public:
  object_string_fn1_t(Func func) : m_func(func) {}
  
  virtual torrent::Object operator () (const torrent::Object& arg1) { return torrent::Object(m_func(arg1.as_string())); }

private:
  Func m_func;
};

template <typename Func>
class object_string_fn1_t<Func, void> : public rak::function_base1<torrent::Object, const torrent::Object&> {
public:
  object_string_fn1_t(Func func) : m_func(func) {}
  
  virtual torrent::Object operator () (const torrent::Object& arg1) {
    m_func(arg1.as_string());

    return torrent::Object();
  }

private:
  Func m_func;
};

template <typename Return> object_void_fn_t<Return (*)(void), Return>* object_fn(Return (*func)(void)) { return new object_void_fn_t<Return (*)(void), Return>(func); }

template <typename Func> object_void_fn_t<Func>*    object_void_fn(Func func)       { return new object_void_fn_t<Func>(func); }
  //template <typename Func> object_void_fn_t<Func>*    object_void_value_fn(Func func) { return new object_void_fn_t<Func, int64_t>(func); }
template <typename Func> object_value_fn1_t<Func>*  object_value_fn(Func func)      { return new object_value_fn1_t<Func>(func); }
template <typename Func> object_string_fn1_t<Func>* object_string_fn(Func func)     { return new object_string_fn1_t<Func>(func); }

}

#endif
