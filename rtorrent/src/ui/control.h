#ifndef RTORRENT_UI_CONTROL_H
#define RTORRENT_UI_CONTROL_H

#include "core/manager.h"
#include "display/manager.h"
#include "input/manager.h"

namespace ui {

class Control {
public:
  Control() {}
  
  core::Manager&    get_core()    { return m_core; }
  display::Manager& get_display() { return m_display; }
  input::Manager&   get_input()   { return m_input; }

private:
  Control(const Control&);
  void operator = (const Control&);

  core::Manager     m_core;
  display::Manager  m_display;
  input::Manager    m_input;
};

}

#endif
