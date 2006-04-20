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

// Parts of this seems ugly in an attempt to avoid copying
// data. Propably need to rewrite torrent::Object.

#ifndef RTORRENT_UTILS_VARIABLE_GENERIC_H
#define RTORRENT_UTILS_VARIABLE_GENERIC_H

#include <cstdio>
#include <string>
#include <limits>
#include <inttypes.h>
#include <rak/functional_fun.h>
#include <torrent/object.h>
#include <torrent/exceptions.h>

#include "variable.h"

namespace utils {

class VariableAny : public Variable {
public:
  VariableAny(const torrent::Object& v = torrent::Object()) :
    m_variable(v) {}
  virtual ~VariableAny();

  virtual const torrent::Object&  get();
  virtual void                    set(const torrent::Object& arg);

private:
  torrent::Object    m_variable;
};

class VariableValue : public Variable {
public:
  VariableValue(int64_t v) : m_variable(v) {}
  virtual ~VariableValue();

  virtual const torrent::Object& get();
  virtual void                    set(const torrent::Object& arg);

private:
  torrent::Object    m_variable;
};

class VariableBool : public Variable {
public:
  VariableBool(bool state) : m_variable(state ? (int64_t)1 : (int64_t)0) {}
  VariableBool(const torrent::Object& v = torrent::Object((int64_t)0)) { set(v); }
  virtual ~VariableBool();

  virtual const torrent::Object& get();
  virtual void        set(const torrent::Object& arg);

private:
  torrent::Object    m_variable;
};

class VariableObject : public Variable {
public:
  typedef torrent::Object::type_type Type;

  VariableObject(torrent::Object* b,
		  const std::string& root,
		  const std::string& key,
		  Type t = torrent::Object::TYPE_NONE) :
    m_bencode(b), m_root(root), m_key(key), m_type(t) {}
  virtual ~VariableObject();

  virtual const torrent::Object& get();
  virtual void        set(const torrent::Object& arg);

private:
  torrent::Object*   m_bencode;
  std::string         m_root;
  std::string         m_key;
  Type                m_type;
};

//
// New and pretty.
//

class VariableValueSlot : public Variable {
public:
  typedef rak::function0<value_type>        slot_get_type;
  typedef rak::function1<void, value_type>  slot_set_type;
  typedef std::pair<value_type, value_type> range_type;

  template <typename SlotGet, typename SlotSet>
  VariableValueSlot(SlotGet* slotGet, SlotSet* slotSet, unsigned int base = 0, unsigned int unit = 1,
		    range_type range = range_type(std::numeric_limits<value_type>::min(), std::numeric_limits<value_type>::max())) :
    m_base(base),
    m_unit(unit),
    m_range(range) {

    m_slotGet.set(rak::convert_fn<value_type>(slotGet));
    m_slotSet.set(rak::convert_fn<void, value_type>(slotSet));
  }

  virtual const torrent::Object& get();
  virtual void                   set(const torrent::Object& arg);

private:
  slot_get_type       m_slotGet;
  slot_set_type       m_slotSet;

  unsigned int        m_base;
  unsigned int        m_unit;
  range_type          m_range;

  // Store the cache here to avoid unnessesary copying and such. This
  // should not result in any unresonable memory usage since few
  // strings will be very large.
  torrent::Object     m_cache;
};

class VariableStringSlot : public Variable {
public:
  typedef rak::function0<string_type>              slot_get_type;
  typedef rak::function1<void, const string_type&> slot_set_type;

  template <typename SlotGet, typename SlotSet>
  VariableStringSlot(SlotGet* slotGet, SlotSet* slotSet) {
    m_slotGet.set(rak::convert_fn<string_type>(slotGet));
    m_slotSet.set(rak::convert_fn<void, const string_type&>(slotSet));
  }

  virtual const torrent::Object& get();
  virtual void                   set(const torrent::Object& arg);

private:
  slot_get_type       m_slotGet;
  slot_set_type       m_slotSet;

  // Store the cache here to avoid unnessesary copying and such. This
  // should not result in any unresonable memory usage since few
  // strings will be very large.
  torrent::Object     m_cache;
};


}

#endif
