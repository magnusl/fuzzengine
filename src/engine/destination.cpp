#include "destination.h"
#include "endian.h"
#include "ioerror.h"

namespace fuzzer {

namespace io {

Destination::Destination() : _big_endian(true)
{
}

Destination::~Destination()
{
}

void Destination::write_big_endian()
{
    _big_endian = true;
}

void Destination::write_little_endian()
{
    _big_endian = false;
}

void Destination::writeU8(uint8_t value)
{
    if (!write(&value, sizeof(uint8_t))) {
        throw IoException("Failed to write U8.");
    }
}

void Destination::writeU16(uint16_t value)
{
    value = host16_to_be(value);
    if (!write(&value, sizeof(uint16_t))) {
        throw IoException("Failed to write U16.");
    }
}

void Destination::writeU24(uint32_t value)
{
    throw IoException("Failed to write U24.");
}

void Destination::writeU32(uint32_t value)
{
    value = host32_to_be(value);
    if (!write(&value, sizeof(uint32_t))) {
        throw IoException("Failed to write U32.");
    }
}

void Destination::writeU64(uint64_t value)
{
    value = host64_to_be(value);
    if (!write(&value, sizeof(uint64_t))) {
        throw IoException("Failed to write U64.");
    }
}

}

}