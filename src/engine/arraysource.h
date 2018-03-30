#ifndef _ARRAYSOURCE_H_
#define _ARRAYSOURCE_H_

#include "source.h"
#include <stdint.h>

namespace fuzzer {

namespace io {

///
/// \class  ArraySource
///
class ArraySource : public Source
{
public:
    ///
    /// \brief  constructor
    ///
    ArraySource(const void * data, size_t size);

    ///
    /// \brief  read data from the array.
    ///
    virtual bool read(void * dst, size_t count);

protected:
    const uint8_t * _data;
    size_t          _size;
    size_t          _offset;
}; 

} // namespace runtime

} // namespace fuzzer

#endif
