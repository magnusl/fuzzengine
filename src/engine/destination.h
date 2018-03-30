#ifndef _DESTINATION_H_
#define _DESTINATION_H_

#include <stdint.h>

namespace fuzzer {

namespace io {

///
/// \class  Destination
/// \brief
///
class Destination
{
public:
    Destination();

    ///
    /// \brief  Virtual destructor
    ///
    virtual ~Destination();

    void write_big_endian();
    void write_little_endian();

    void writeU8(uint8_t);
    void writeU16(uint16_t);
    void writeU24(uint32_t);
    void writeU32(uint32_t);
    void writeU64(uint64_t);

    ///
    /// \brief  Write data to the destination
    ///
    virtual bool write(const void * dst, size_t count) = 0;

protected:
    bool _big_endian;
};

} // namespace io

} // namespace fuzzer

#endif