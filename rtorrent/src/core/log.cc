#include "config.h"

#include <algorithm>

#include "log.h"
#include "rak/functional.h"

namespace core {

void
Log::push_front(const std::string& msg) {
  Base::push_front(Type(utils::Timer::cache(), msg));

  if (size() > 50)
    Base::pop_back();

  m_signalUpdate.emit();
}

Log::iterator
Log::find_older(utils::Timer t) {
  return std::find_if(begin(), end(), rak::on(rak::mem_ptr_ref(&Type::first), std::bind2nd(std::less_equal<utils::Timer>(), t)));
}

}
