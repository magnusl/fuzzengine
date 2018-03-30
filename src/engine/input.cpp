#include "input.h"
#include <vector>

namespace fuzzer {

namespace io {

///
/// \brief  Hidden implementation class
/// 
class Input::Implementation
{
public:
    ~Implementation();
    bool getUnsigned(size_t index, uint32_t & value);
    std::vector<InputItem>  _items;
};

Input::Input()
{
    _impl = new Implementation();
}

Input::~Input()
{
    delete _impl;
}

Input::Implementation::~Implementation()
{
    for(size_t i = 0; i < _items.size(); ++i) {
        InputItem & item = _items[i];
        if (item.type == InputItem::VARRAY) {
            if (item.u.varray.data) {
                delete [] item.u.varray.data;
            }
        }
    }
}

bool Input::Implementation::getUnsigned(size_t index, uint32_t & value)
{
    if (index >= _items.size()) {
        return false;
    }
    InputItem & item = _items[index];
    switch(item.type) {
    case InputItem::BYTE:   value = item.u.byte; return true;
    case InputItem::WORD:   value = item.u.word; return true;
    case InputItem::DWORD:  value = item.u.dword; return true;
    default:            return false;
    }
}

const InputItem * Input::get(size_t id) const
{
    if (id >= _impl->_items.size()) {
        return false;
    }
    return &_impl->_items[id];
}

bool Input::read(Source & source)
{
#if 0
    if(_impl == nullptr) {
        return false;
    }

    for(size_t i = 0, count = _impl->_items.size(); i < count; ++i) {
        InputItem & item = _impl->_items[i];
        switch(item.type) {
        case InputItem::BYTE:   if (!source.readU8(item.u.byte)) { return false; } break;
        case InputItem::WORD:   if (!source.u16(item.u.word)) { return false; } break;
        case InputItem::DWORD:  if (!source.u32(item.u.dword)) { return false; } break;
        case InputItem::QWORD:  if (!source.u64(item.u.qword)) { return false; } break;
        case InputItem::VARRAY:
            {
                // variable length array where the length field was transfered earlier
                if (item.u.varray.ref_id < i) {
                    uint32_t count;
                    if (!_impl->getUnsigned(item.u.varray.ref_id, count)) {
                        return false;
                    }
                    if ((count > item.u.varray.max) || 
                        (count > static_cast<uint32_t>(std::numeric_limits<int32_t>::max())))
                    {
                        return false;
                    }
                    if (count) {
                        item.u.varray.data = new (std::nothrow) uint8_t[count];
                        if (!source.read(item.u.varray.data, static_cast<int32_t>(count))) {
                            delete [] item.u.varray.data;
                            item.u.varray.data  = 0;
                            item.u.varray.count = 0;
                            return false;
                        }
                        item.u.varray.count = count;
                    } else {
                        item.u.varray.count = 0;
                        item.u.varray.data  = nullptr;
                    }
                } else {
                    return false;
                }
                break;
            }
        }
    }
#endif
    return true;
}

size_t Input::u8(bool capture)
{
    size_t id = _impl->_items.size();
    InputItem item;
    item.type       = InputItem::BYTE;
    item._capture   = capture;
    _impl->_items.push_back(item);

    return id;
}

size_t Input::u16(bool capture)
{
    size_t id = _impl->_items.size();
    InputItem item;
    item.type       = InputItem::WORD;
    item._capture   = capture;
    _impl->_items.push_back(item);

    return id;
}

size_t Input::u24(bool capture)
{
    size_t id = _impl->_items.size();
    InputItem item;
    item.type       = InputItem::WORD24;
    item._capture   = capture;
    _impl->_items.push_back(item);

    return id;
}

size_t Input::u32(bool capture)
{
    size_t id = _impl->_items.size();
    InputItem item;
    item.type       = InputItem::DWORD;
    item._capture   = capture;
    _impl->_items.push_back(item);

    return id;
}

size_t Input::u64(bool capture)
{
    size_t id = _impl->_items.size();
    InputItem item;
    item.type       = InputItem::QWORD;
    item._capture   = capture;
    _impl->_items.push_back(item);

    return id;
}

size_t Input::varray(size_t ref_id, size_t max, bool capture)
{
    size_t id = _impl->_items.size();
    InputItem item;
    item.type               = InputItem::VARRAY;
    item.u.varray.max       = max;
    item.u.varray.ref_id    = ref_id;
    item.u.varray.data      = 0;
    item._capture           = capture;
    _impl->_items.push_back(item);

    return id;
}

}

}