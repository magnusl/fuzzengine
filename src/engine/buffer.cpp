#include "buffer.h"
#include "endian.h"

namespace fuzzer {

namespace runtime {

Buffer::Buffer(std::vector<uint8_t> & dst) : _dst(dst)
{
}

bool Buffer::write(const void * dst, size_t count)
{
    if (!count) {
        return false;
    }
    size_t offset = _dst.size();
    _dst.resize(_dst.size() + count);
    memcpy(&_dst[offset], dst, count);
    return true;
}

} // namespace runtime

} // namespace fuzzer
