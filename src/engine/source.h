#ifndef _SOURCE_H_
#define _SOURCE_H_

#include <stdint.h>

namespace fuzzer {

namespace io {

///
/// \class  Source
/// \brief  Abstraction of an input source from which binary data can be read.
///
class Source
{
public:
    Source();

    ///
    /// \brief  Virtual destructor
    ///
    virtual ~Source();

    void read_big_endian();
    void read_little_endian();

    uint8_t readU8();
    uint16_t readU16();
    uint32_t readU24();
    uint32_t readU32();
    uint64_t readU64();

    ///
    /// \brief  Read data from the source
    ///
    virtual bool read(void * dst, size_t count) = 0;

protected:
    bool _big_endian;
};

} // namespace io

} // namespace fuzzer

#endif