#include "config.h"

#include "exceptions.h"
#include "peer.h"
#include "peer_connection.h"

namespace torrent {

std::string
Peer::get_id() {
  return ((PeerConnection*)m_ptr)->peer().id();
}

std::string
Peer::get_dns() {
  return ((PeerConnection*)m_ptr)->peer().dns();
}

uint16_t
Peer::get_port() {
  return ((PeerConnection*)m_ptr)->peer().port();
}

bool
Peer::get_local_choked() {
  return ((PeerConnection*)m_ptr)->up().c_choked();
}

bool
Peer::get_local_interested() {
  return ((PeerConnection*)m_ptr)->up().c_interested();
}

bool
Peer::get_remote_choked() {
  return ((PeerConnection*)m_ptr)->down().c_choked();
}

bool
Peer::get_remote_interested() {
  return ((PeerConnection*)m_ptr)->down().c_interested();
}

bool
Peer::get_choke_delayed() {
  return ((PeerConnection*)m_ptr)->chokeDelayed();
}

bool
Peer::get_snubbed() {
  return ((PeerConnection*)m_ptr)->throttle().get_snub();
}

// Bytes per second.
uint32_t
Peer::get_rate_down() {
  return ((PeerConnection*)m_ptr)->throttle().down().rate_quick();
}

uint32_t
Peer::get_rate_up() {
  return ((PeerConnection*)m_ptr)->throttle().up().rate_quick();
}

uint64_t
Peer::get_transfered_down() {
  return ((PeerConnection*)m_ptr)->throttle().down().total();
}  

uint64_t
Peer::get_transfered_up() {
  return ((PeerConnection*)m_ptr)->throttle().up().total();
}  

uint32_t
Peer::get_incoming_queue_size() {
  return ((PeerConnection*)m_ptr)->down().c_list().size();
}

uint32_t
Peer::get_outgoing_queue_size() {
  return ((PeerConnection*)m_ptr)->up().c_list().size();
}  

uint32_t
Peer::get_incoming_index(uint32_t pos) {
  for (PeerConnection::PieceList::const_iterator itr = ((PeerConnection*)m_ptr)->down().c_list().begin();
       itr != ((PeerConnection*)m_ptr)->down().c_list().end(); ++itr, --pos)
    if (!pos)
      return itr->c_index();

  throw client_error("get_incoming_index(pos) out of range");
}

  uint32_t             get_incoming_offset(uint32_t pos);
  uint32_t             get_incoming_length(uint32_t pos);

// Currently needs to copy the data once to a std::string. But 
// since gcc does ref counted std::string, you can inexpensively
// copy the resulting string. Will consider making BitField use a
// std::string.
const unsigned char*
Peer::get_bitfield_data() {
  return (const unsigned char*)((PeerConnection*)m_ptr)->bitfield().data();
}

uint32_t
Peer::get_bitfield_size() {
  return ((PeerConnection*)m_ptr)->bitfield().sizeBits();
}

void
Peer::set_snubbed(bool v) {
  ((PeerConnection*)m_ptr)->throttle().set_snub(v);

  if (v)
    ((PeerConnection*)m_ptr)->choke(true);
}

}
