#ifndef LIBTORRENT_TRACKER_HTTP_H
#define LIBTORRENT_TRACKER_HTTP_H

#include <list>
#include <iosfwd>
#include <inttypes.h>

#include "bencode.h"
#include "peer_info.h"
#include "tracker_state.h"

struct sockaddr_in;

namespace torrent {

class Http;

// TODO: Use a base class when we implement UDP tracker support.
class TrackerHttp {
public:
  typedef std::list<PeerInfo> PeerList;

  TrackerHttp();
  ~TrackerHttp();

  void               set_url(const std::string& url)   { m_url = url; }
  void               set_hash(const std::string& hash) { m_hash = hash; }
  void               set_me(const PeerInfo& me)        { m_me = me; }
  void               set_compact(bool c)               { m_compact = c; }
  
  void               send_state(TrackerState state, uint64_t down, uint64_t up, uint64_t left);

  void               close();

  bool               is_busy() { return m_data != NULL; }

  // New peers.
  // Interval      - 0 if not received or invalid.
  typedef sigc::signal2<void, const PeerList&, int> SignalDone;
  SignalDone&        signal_done() { return m_done; }

  typedef sigc::signal1<void, std::string> SignalFailed;
  SignalFailed&      signal_failed()        { return m_failed; }

private:
  // Don't allow ctor.
  TrackerHttp(const TrackerHttp& t);
  void operator = (const TrackerHttp& t);

  void               escape_string(const std::string& src, std::ostream& stream);
  
  void               parse_peers_normal(PeerList& l, const bencode::List& b);
  void               parse_peers_compact(PeerList& l, const std::string& s);

  void               receive_done();
  void               receive_failed(std::string msg);

  PeerInfo           parse_peer(const bencode& b);

  Http*              m_get;
  std::stringstream* m_data;

  std::string        m_url;
  std::string        m_hash;

  bool               m_compact;

  PeerInfo           m_me;

  SignalDone         m_done;
  SignalFailed       m_failed;
};

} // namespace torrent

#endif // LIBTORRENT_TRACKER_QUERY_H
