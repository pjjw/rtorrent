#ifndef RTORRENT_INPUT_MANAGER_H
#define RTORRENT_INPUT_MANAGER_H

#include <list>

namespace input {

class Bindings;
class TextInput;

class Manager : private std::list<Bindings*> {
public:
  typedef std::list<Bindings*> Base;

  using Base::iterator;
  using Base::const_iterator;
  using Base::reverse_iterator;
  using Base::const_reverse_iterator;

  using Base::begin;
  using Base::end;
  using Base::rbegin;
  using Base::rend;

  using Base::push_back;
  using Base::push_front;

  Manager() : m_textInput(NULL) {}

  void erase(Bindings* b);

  void pressed(int key);

  void set_text_input(TextInput* input = NULL) { m_textInput = input; }

  // Slot for unreacted keys.

private:
  TextInput* m_textInput;
};

}

#endif
