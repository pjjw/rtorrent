#include "config.h"

#include <inttypes.h>

#include "algo/algo.h"
#include "torrent/exceptions.h"
#include "content/delegator.h"
#include "content/delegator_reservee.h"

#include "request_list.h"

using namespace algo;

namespace torrent {

const Piece*
RequestList::delegate() {
  DelegatorReservee* r = m_delegator->delegate(*m_bitfield, m_affinity);

  if (r) {
    m_affinity = r->get_piece().get_index();
    m_reservees.push_back(r);

    return &r->get_piece();

  } else {
    return NULL;
  }
}

void
RequestList::cancel() {
  if (m_downloading)
    throw internal_error("RequestList::cancel(...) called while is_downloading() == true");

  cancel_range(m_reservees.end());
}

void
RequestList::stall() {
  std::for_each(m_reservees.begin(), m_reservees.end(),
		call_member(&DelegatorReservee::set_stalled, value(true)));
}

bool
RequestList::downloading(const Piece& p) {
  if (m_downloading)
    throw internal_error("RequestList::downloading(...) bug, m_downloaing is already set");

  remove_invalid();

  ReserveeList::iterator itr =
    std::find_if(m_reservees.begin(), m_reservees.end(),
		 eq(ref(p), call_member(&DelegatorReservee::get_piece)));
  
  if (itr == m_reservees.end() || !m_delegator->downloading(**itr))
    return false;

  if ((*m_delegator->get_select().get_bitfield())[p.get_index()])
    throw internal_error("RequestList::downloading(...) called with a piece index we already have");

  cancel_range(itr);
  
  m_downloading = true;
  m_piece = m_reservees.front()->get_piece();
  
  return true;
}

// Must clear the downloading piece.
void
RequestList::finished() {
  if (!m_downloading || !m_reservees.size())
    throw internal_error("RequestList::finished() called without a downloading piece");

  m_delegator->finished(*m_reservees.front());

  delete m_reservees.front();;
  m_reservees.pop_front();

  m_downloading = false;
}

void
RequestList::skip() {
  if (!m_downloading || !m_reservees.size())
    throw internal_error("RequestList::skip() called without a downloading piece");

  delete m_reservees.front();
  m_reservees.pop_front();

  m_downloading = false;
}

bool
RequestList::has_index(unsigned int i) {
  return std::find_if(m_reservees.begin(), m_reservees.end(),
		      bool_and(call_member(&DelegatorReservee::is_valid),
			       eq(value((signed int)i), call_member(call_member(&DelegatorReservee::get_piece), &Piece::get_index))))
    != m_reservees.end();
}

void
RequestList::cancel_range(ReserveeList::iterator end) {
  while (m_reservees.begin() != end) {
    m_delegator->cancel(*m_reservees.front());
    
    delete m_reservees.front();
    m_reservees.pop_front();
  }
}

unsigned int
RequestList::remove_invalid() {
  unsigned int count = 0;
  ReserveeList::iterator itr;

  // Could be more efficient, but rarely do we find any.
  while ((itr = std::find_if(m_reservees.begin(), m_reservees.end(),
			     bool_not(call_member(&DelegatorReservee::is_valid))))
	 != m_reservees.end()) {
    count++;
    delete *itr;
    m_reservees.erase(itr);
  }

  return count;
}

}
