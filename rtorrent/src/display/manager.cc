#include "config.h"

#include <stdexcept>
#include <algorithm>

#include "rak/functional.h"

#include "canvas.h"
#include "manager.h"
#include "window.h"

namespace display {

Manager::iterator
Manager::erase(Window* w) {
  iterator itr = std::find(begin(), end(), w);

  if (itr == end())
    throw std::logic_error("Manager::erase(...) did not find the window");

  return Base::erase(itr);
}

Manager::iterator
Manager::find(Window* w) {
  return std::find(begin(), end(), w);
}

void
Manager::adjust_layout() {
  int countDynamic = 0;
  int staticHeight = 0;

  std::for_each(begin(), end(), rak::if_then(std::mem_fun(&Window::is_active), rak::accumulate(staticHeight, std::mem_fun(&Window::get_min_height))));
  std::for_each(begin(), end(), rak::if_then(std::mem_fun(&Window::is_active), rak::accumulate(countDynamic, std::mem_fun(&Window::is_dynamic))));

  int dynamic = std::max(0, Canvas::get_screen_height() - staticHeight);
  int height = 0, h;

  for (iterator itr = begin(); itr != end(); ++itr, height += h) {
    h = 0;

    if (!(*itr)->is_active())
      continue;

    if ((*itr)->is_dynamic()) {
      dynamic -= h = (dynamic + countDynamic - 1) / countDynamic;
      countDynamic--;
    } else {
      h = 0;
    }

    h += (*itr)->get_min_height();

    (*itr)->resize(0, height, Canvas::get_screen_width(), h);
    (*itr)->mark_dirty();
  }
}

void
Manager::do_update() {
  Canvas::refresh_std();

  std::for_each(begin(), end(), rak::if_then(std::mem_fun(&Window::is_active), rak::if_then(std::mem_fun(&Window::is_dirty),
											    std::mem_fun(&Window::redraw))));
  std::for_each(begin(), end(), rak::if_then(std::mem_fun(&Window::is_active), std::mem_fun(&Window::refresh)));

  Canvas::do_update();
}

}
