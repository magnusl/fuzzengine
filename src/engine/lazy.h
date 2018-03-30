#ifndef _LAZY_H_
#define _LAZY_H_

#include "buffer.h"

namespace fuzzer {

namespace runtime {

class Template;

///
/// \class  LazyEvaluation
///
class LazyEvaluation
{
public:
    ///
    /// \brief  evaluate and output data to buffer
    ///
    virtual void evaluate(Buffer &) = 0;
};

} // namespace runtime

} // namespace fuzzer

#endif