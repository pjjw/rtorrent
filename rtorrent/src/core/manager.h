#ifndef RTORRENT_CORE_MANAGER_H
#define RTORRENT_CORE_MANAGER_H

#include "download_list.h"
#include "download_store.h"
#include "hash_queue.h"
#include "http_queue.h"
#include "poll.h"

namespace core {

class Manager {
public:
  typedef sigc::slot1<void, DownloadList::iterator> SlotReady;
  typedef sigc::slot0<void>                         SlotFailed;

  Manager() : m_portFirst(6890), m_portLast(6999) {}

  DownloadList&   get_download_list()                 { return m_downloadList; }
  DownloadStore&  get_download_store()                { return m_downloadStore; }
  HashQueue&      get_hash_queue()                    { return m_hashQueue; }
  HttpQueue&      get_http_queue()                    { return m_httpQueue; }

  Poll&           get_poll()                          { return m_poll; }

  void            initialize();
  void            cleanup();

  void            insert(const std::string& uri);
  void            erase(DownloadList::iterator itr);

  void            start(Download* d);
  void            stop(Download* d);

  void            set_port_range(int a, int b)        { m_portFirst = a; m_portLast = b; }

private:
  void            receive_http_done(CurlGet* http);

  void            create_file(const std::string& uri);
  void            create_http(const std::string& uri);

  DownloadList    m_downloadList;
  DownloadStore   m_downloadStore;
  HashQueue       m_hashQueue;
  HttpQueue       m_httpQueue;
  Poll            m_poll;

  int             m_portFirst;
  int             m_portLast;
};

}

#endif
