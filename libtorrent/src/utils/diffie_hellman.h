// libTorrent - BitTorrent library
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

#ifndef LIBTORRENT_DIFFIE_HELLMAN_H
#define LIBTORRENT_DIFFIE_HELLMAN_H

#include "config.h"

#include <string>

#ifdef USE_OPENSSL
#include <openssl/dh.h>
#endif

namespace torrent {

class DiffieHellman {
public:
  DiffieHellman(const unsigned char prime[], int primeLength,
                const unsigned char generator[], int generatorLength);
  ~DiffieHellman();

  void                compute_secret(const unsigned char pubkey[], unsigned int length);
  void                store_pub_key(unsigned char* dest, unsigned int length);

  unsigned int        size() const         { return m_size; }

  const char*         c_str() const        { return m_secret; }
  std::string         secret_str() const   { return std::string(m_secret, m_size); }

private:
  DiffieHellman(const DiffieHellman& dh);
  DiffieHellman& operator = (const DiffieHellman& dh);

#ifdef USE_OPENSSL
  DH*                 m_dh;
#endif
  char*               m_secret;
  unsigned int        m_size;
};

};

#endif
