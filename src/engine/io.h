#ifndef _IO_H_
#define _IO_H_

#include <stdint.h>
#include "source.h"
#include "destination.h"

namespace fuzzer {

namespace io {

///
/// \class  Ipc
/// \brief  Communications channel between the fuzzer runtime and the
///         process under fuzzing.
///
class Ipc : public Source, public Destination
{
public:
    /// \brief  virtual destructor
    virtual ~Ipc() {}
};

} // namespace bytecode

} // namespace fuzzer

#endif