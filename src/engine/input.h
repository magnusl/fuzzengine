#ifndef _INPUT_H_
#define _INPUT_H_

#include <stdint.h>
#include "source.h"

namespace fuzzer {

namespace io {

struct InputItem {
    enum {
        BYTE,
        WORD,
        WORD24,
        DWORD,
        QWORD,
        FLOAT,
        DOUBLE,
        BUFFER,
        VARRAY
    } type;

    union {
        uint8_t             byte;
        uint16_t            word;
        uint32_t            dword;
        uint64_t            qword;
        float               spf;
        double              dpf;
        struct {
            size_t  ref_id;
            size_t  count;
            size_t  max;
            void *  data;
        } varray;
    } u;

    bool    _capture;
};

///
/// \class  Input
/// \brief  Utility class for reading generic data from an input source.
////        The interface schedules the reading of various fields from
////        which can be captured for later use.
///
class Input
{
public:
    Input();
    virtual ~Input();

    size_t u8(bool capture = true);
    size_t u16(bool capture = true);
    size_t u24(bool capture = true);
    size_t u32(bool capture = true);
    size_t u64(bool capture = true);

    /// variable length array, id is from a previous captured value
    size_t varray(size_t id, size_t max, bool capture = true);

    /// read the data from the source
    virtual bool read(Source &);

    /// interface for accessing captured values
    const InputItem * get(size_t id) const;

protected:
    class Implementation;
    Implementation * _impl;
};

} // namespace runtime

} // namespace fuzzer

#endif