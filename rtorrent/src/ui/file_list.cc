#include "config.h"

#include <stdexcept>

#include "display/window_file_list.h"

#include "control.h"
#include "file_list.h"

namespace ui {

FileList::FileList(Control* c, core::Download* d) :
  m_download(d),
  m_window(NULL),
  m_control(c),
  m_focus(0) {

  m_bindings[' '] = sigc::mem_fun(*this, &FileList::receive_priority);
  m_bindings[KEY_DOWN] = sigc::mem_fun(*this, &FileList::receive_next);
  m_bindings[KEY_UP] = sigc::mem_fun(*this, &FileList::receive_prev);
}

void
FileList::activate(MItr mItr) {
  if (m_window != NULL)
    throw std::logic_error("ui::FileList::activate(...) called on an object in the wrong state");

  m_control->get_input().push_front(&m_bindings);

  *mItr = m_window = new WFileList(m_download, &m_focus);
}

void
FileList::disable() {
  if (m_window == NULL)
    throw std::logic_error("ui::FileList::disable(...) called on an object in the wrong state");

  m_control->get_input().erase(&m_bindings);

  delete m_window;
  m_window = NULL;
}

void
FileList::receive_next() {
  if (m_window == NULL)
    throw std::logic_error("ui::FileList::receive_next(...) called on a disabled object");

  if (++m_focus >= m_download->get_download().get_entry_size())
    m_focus = 0;

  m_window->mark_dirty();
}

void
FileList::receive_prev() {
  if (m_window == NULL)
    throw std::logic_error("ui::FileList::receive_prev(...) called on a disabled object");

  if (m_download->get_download().get_entry_size() == 0)
    return;

  if (m_focus != 0)
    --m_focus;
  else 
    m_focus = m_download->get_download().get_entry_size() - 1;

  m_window->mark_dirty();
}

void
FileList::receive_priority() {
  if (m_window == NULL)
    throw std::logic_error("ui::FileList::receive_prev(...) called on a disabled object");

  if (m_focus >= m_download->get_download().get_entry_size())
    return;

  torrent::Entry e = m_download->get_download().get_entry(m_focus);

  switch (e.get_priority()) {
  case torrent::Entry::STOPPED:
    e.set_priority(torrent::Entry::HIGH);
    break;

  case torrent::Entry::NORMAL:
    e.set_priority(torrent::Entry::STOPPED);
    break;

  case torrent::Entry::HIGH:
    e.set_priority(torrent::Entry::NORMAL);
    break;
	
  default:
    e.set_priority(torrent::Entry::NORMAL);
    break;
  };

  m_window->mark_dirty();
}

}
