#include "source.h"
#include "endian.h"
#include "ioerror.h"

namespace fuzzer {

namespace io {

Source::Source() : _big_endian(true)
{
}

Source::~Source()
{
}

void Source::read_big_endian()
{
    _big_endian = true;
}

void Source::read_little_endian()
{
    _big_endian = false;
}

uint8_t Source::readU8(void)
{
    uint8_t value;
    if (!read(&value, sizeof(uint8_t))) {
        throw io::IoException("Failed to read U8 from source.");    
    }
    return value;
}

uint16_t Source::readU16()
{
    uint16_t value;
    if (!read(&value, sizeof(value))) {
        throw io::IoException("Failed to read U16 from source.");   
    }
    return _big_endian ? be_to_host16(value) : le_to_host16(value);
}

uint32_t Source::readU24()
{
    throw io::IoException("Failed to read U24 from source.");   
}

uint32_t Source::readU32()
{
    uint32_t value;
    if (!read(&value, sizeof(value))) {
        throw io::IoException("Failed to read U32 from source.");   
    }
    return _big_endian ? be_to_host32(value) : le_to_host32(value);
}

uint64_t Source::readU64()
{
    uint64_t value;
    if (!read(&value, sizeof(value))) {
        throw io::IoException("Failed to read U64 from source.");   
    }
    return _big_endian ? be_to_host64(value) : le_to_host64(value);
}

} // namespace runtime

} // namespace fuzzer
