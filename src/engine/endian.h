#ifndef _ENDIAN_H_
#define _ENDIAN_H_

#include <stdint.h>

namespace fuzzer {

namespace io {

#if defined(_M_IX86) || defined(__i386__)
#define ARCH_LITTLE_ENDIAN                  /* x86 is little endian */
#define UNALIGNED_ACCESS_ALLOWED            /* x86 allows for unaligned memory accesses */
#else
#error "platform not supported."
#endif

#define swap32(x) ((((x) >> 24) & 0xff) | (((x) >> 8) & 0xff00) | (((x) << 8) & 0xff0000) | ((x) << 24))
#define swap64(x)  ((((x) & 0xff00000000000000ull) >> 56)             \
    | (((x) & 0x00ff000000000000ull) >> 40)                                 \
    | (((x) & 0x0000ff0000000000ull) >> 24)                                 \
    | (((x) & 0x000000ff00000000ull) >> 8)                                  \
    | (((x) & 0x00000000ff000000ull) << 8)                                  \
    | (((x) & 0x0000000000ff0000ull) << 24)                                 \
    | (((x) & 0x000000000000ff00ull) << 40)                                 \
    | (((x) & 0x00000000000000ffull) << 56))

#define swap16(x)       ((((x) & 0xff) << 8) | ((x) >> 8))

///////////////////////////////////////////////////////////////////////////////
//                              Big endian to host                           //
///////////////////////////////////////////////////////////////////////////////
inline uint16_t be_to_host16(uint16_t x)
{
#ifdef ARCH_LITTLE_ENDIAN
    // from big to little
    return swap16(x);
#else
    // from big to big
    return x;
#endif
}

inline uint32_t be_to_host32(uint32_t x)
{
#ifdef ARCH_LITTLE_ENDIAN
    // from big to little
    return swap32(x);
#else
    // from big to big
    return x;
#endif
}

inline uint64_t be_to_host64(uint64_t x)
{
#ifdef ARCH_LITTLE_ENDIAN
    // from big to little
    return swap64(x);
#else
    // from big to big
    return x;
#endif
}

///////////////////////////////////////////////////////////////////////////////
//                              Little endian to host                        //
///////////////////////////////////////////////////////////////////////////////

inline uint16_t le_to_host16(uint16_t x)
{
#ifdef ARCH_LITTLE_ENDIAN
    // from little to little
    return x;
#else
    // from litte to big
    return swap16(x);
#endif
}

inline uint32_t le_to_host32(uint32_t x)
{
#ifdef ARCH_LITTLE_ENDIAN
    // from little to little
    return x;
#else
    // from litte to big
    return swap32(x);
#endif
}

inline uint64_t le_to_host64(uint64_t x)
{
#ifdef ARCH_LITTLE_ENDIAN
    // from little to little
    return x;
#else
    // from litte to big
    return swap64(x);
#endif
}

///////////////////////////////////////////////////////////////////////////////
//                              Host to big endian                           //
///////////////////////////////////////////////////////////////////////////////

inline uint16_t host16_to_be(uint16_t x)
{
#ifdef ARCH_LITTLE_ENDIAN
    return swap16(x);
#else
    // from big to big
    return x;
#endif
}

inline uint32_t host32_to_be(uint32_t x)
{
#ifdef ARCH_LITTLE_ENDIAN
    return swap32(x);
#else
    // from big to big
    return x;
#endif
}

inline uint64_t host64_to_be(uint64_t x)
{
#ifdef ARCH_LITTLE_ENDIAN
    return swap64(x);
#else
    // from big to big
    return x;
#endif
}

} // namespace io

} // namespace fuzzer

#endif
