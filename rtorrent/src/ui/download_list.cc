#include "config.h"

#include <stdexcept>
#include <torrent/torrent.h>
#include <sigc++/bind.h>

#include "input/bindings.h"
#include "input/text_input.h"
#include "display/window_title.h"
#include "display/window_download_list.h"
#include "display/window_statusbar.h"
#include "display/window_input.h"

#include "control.h"
#include "download.h"
#include "download_list.h"

namespace ui {

DownloadList::DownloadList(core::DownloadList* l, Control* c) :
  m_title(new WTitle("rtorrent " VERSION " - " + torrent::get(torrent::LIBRARY_NAME))),
  m_status(new WStatus),
  m_download(NULL),
  m_list(l),
  m_focus(l->end()),
  m_control(c),
  m_bindings(new input::Bindings),
  m_windowInput(new WInput(new input::TextInput)) {

  m_window = new WList(m_list, &m_focus);

  bind_keys(m_bindings);

  m_windowInput->get_input()->slot_dirty(sigc::mem_fun(*m_windowInput, &WInput::mark_dirty));
}

DownloadList::~DownloadList() {
  delete m_window;
  delete m_title;
  delete m_status;
  delete m_bindings;

  delete m_windowInput->get_input();
  delete m_windowInput;
}

void
DownloadList::activate() {
  m_control->get_display().push_back(m_windowInput);
  m_control->get_display().push_back(m_status);
  m_control->get_display().push_front(m_window);
  m_control->get_display().push_front(m_title);
  m_control->get_input().push_front(m_bindings);
}

void
DownloadList::disable() {
  m_control->get_display().erase(m_windowInput);
  m_control->get_display().erase(m_title);
  m_control->get_display().erase(m_window);
  m_control->get_display().erase(m_status);
  m_control->get_input().erase(m_bindings);
}

void
DownloadList::receive_next() {
  if (m_focus != m_list->end())
    ++m_focus;
  else
    m_focus = m_list->begin();

  mark_dirty();
}

void
DownloadList::receive_prev() {
  if (m_focus != m_list->begin())
    --m_focus;
  else
    m_focus = m_list->end();

  mark_dirty();
}

void
DownloadList::receive_view_download() {
  if (m_focus == m_list->end())
    return;

  if (m_download != NULL)
    throw std::logic_error("DownloadList::receive_view_download() called but m_download != NULL");

  disable();

  m_download = new Download(&*m_focus, m_control);

  m_download->activate();
  m_download->get_bindings()[KEY_LEFT] = sigc::mem_fun(*this, &DownloadList::receive_exit_download);
}

void
DownloadList::receive_exit_download() {
  if (m_download == NULL)
    throw std::logic_error("DownloadList::receive_exit_download() called but m_download == NULL");

  m_download->disable();
  delete m_download;
  m_download = NULL;

  activate();

  m_control->get_display().adjust_layout();
}

void
DownloadList::receive_throttle(int t) {
  m_status->mark_dirty();

  torrent::set(torrent::THROTTLE_ROOT_CONST_RATE, torrent::get(torrent::THROTTLE_ROOT_CONST_RATE) + t * 1024);
}

void
DownloadList::receive_view_input() {
  m_control->get_input().set_text_input(m_windowInput->get_input());

  m_windowInput->set_focus(true);

  (*m_bindings)['\n'] = sigc::mem_fun(*this, &DownloadList::receive_exit_input);
  (*m_bindings)[KEY_ENTER] = sigc::mem_fun(*this, &DownloadList::receive_exit_input);
}

void
DownloadList::receive_exit_input() {
  m_control->get_input().set_text_input();

  m_windowInput->get_input()->clear();
  m_windowInput->set_focus(false);

  m_bindings->erase('\n');
  m_bindings->erase(KEY_ENTER);
}

void
DownloadList::bind_keys(input::Bindings* b) {
  (*b)['a'] = sigc::bind(sigc::mem_fun(*this, &DownloadList::receive_throttle), 1);
  (*b)['z'] = sigc::bind(sigc::mem_fun(*this, &DownloadList::receive_throttle), -1);
  (*b)['s'] = sigc::bind(sigc::mem_fun(*this, &DownloadList::receive_throttle), 5);
  (*b)['x'] = sigc::bind(sigc::mem_fun(*this, &DownloadList::receive_throttle), -5);
  (*b)['d'] = sigc::bind(sigc::mem_fun(*this, &DownloadList::receive_throttle), 50);
  (*b)['c'] = sigc::bind(sigc::mem_fun(*this, &DownloadList::receive_throttle), -50);

  (*b)[KEY_UP]    = sigc::mem_fun(*this, &DownloadList::receive_prev);
  (*b)[KEY_DOWN]  = sigc::mem_fun(*this, &DownloadList::receive_next);
  (*b)[KEY_RIGHT] = sigc::mem_fun(*this, &DownloadList::receive_view_download);

  (*b)[KEY_BACKSPACE] = sigc::mem_fun(*this, &DownloadList::receive_view_input);
}

void
DownloadList::mark_dirty() {
  m_window->mark_dirty();
}

}
