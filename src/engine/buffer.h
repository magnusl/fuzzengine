#ifndef _BUFFER_H_
#define _BUFFER_H_

#include <stdint.h>
#include <vector>
#include "destination.h"

namespace fuzzer {

namespace runtime {

///
/// \class  Buffer
///
class Buffer : public io::Destination
{
public:
    /// construction
    Buffer(std::vector<uint8_t> &);

    virtual bool write(const void * dst, size_t count);

protected:
    std::vector<uint8_t> &  _dst;
};

} // namespace runtime

} // namespace fuzzer

#endif
