#ifndef LIBTORRENT_DOWNLOAD_MAIN_H
#define LIBTORRENT_DOWNLOAD_MAIN_H

#include "bencode.h"
#include "service.h"
#include "settings.h"
#include "download_state.h"
#include "download/download_net.h"

#include <sigc++/connection.h>

namespace torrent {

class TrackerControl;

class DownloadMain : public Service {
public:
  typedef std::list<DownloadMain*> Downloads;

  enum ServiceState {
    CHOKE_CYCLE = 0x1001
  };

  DownloadMain();
  ~DownloadMain();

  void                open();
  void                close();

  void                start();
  void                stop();

  bool                is_open() { return m_state.get_content().is_open(); }
  bool                is_active() { return m_started; }
  bool                is_checked() { return m_checked; }
  bool                is_stopped();

  void                service(int type);

  const std::string&  get_name() const { return m_name; }
  void                set_name(const std::string& s) { m_name = s; }

  void                set_port(uint16_t p) { m_state.get_me().set_port(p); }

  DownloadState&  state()           { return m_state; }
  DownloadNet&    net()             { return m_net; }
  TrackerControl& tracker()         { return *m_tracker; }

  // Carefull with these.
  void setup_delegator();
  void setup_net();
  void setup_tracker();

  static DownloadMain*  getDownload(const std::string& hash);
  static Downloads&     downloads() { return m_downloads; }

  static std::string get_download_id(const std::string& hash);

  static void receive_connection(int fd, const std::string& hash, const PeerInfo& peer);

  void receive_initial_hash();
  void receive_download_done();

private:
  DownloadMain(const DownloadMain&);
  void operator = (const DownloadMain&);

  void setup_start();
  void setup_stop();

  static Downloads m_downloads;
  
  DownloadState m_state;
  DownloadNet   m_net;
  DownloadSettings m_settings;
  TrackerControl* m_tracker;

  std::string m_name;
  bool m_checked;
  bool m_started;

  sigc::connection m_connectionChunkPassed;
  sigc::connection m_connectionChunkFailed;
  sigc::connection m_connectionAddAvailablePeers;
};

} // namespace torrent

#endif // LIBTORRENT_DOWNLOAD_H

