#include "arraysource.h"
#include <cstring>

namespace fuzzer {

namespace io {

ArraySource::ArraySource(const void * data, size_t size) : 
    _data(static_cast<const uint8_t*>(data)),
    _size(size),
    _offset(0)
{
}

bool ArraySource::read(void * dst, size_t count)
{
    size_t num = static_cast<size_t>(count);
    if ((_offset + count) > _size) {
        return false;
    }
    memcpy(dst, _data + _offset, num);
    _offset += num;
    return true;
}


} // namespace runtime

} // namespace fuzzer