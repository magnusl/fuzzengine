#ifndef _MUTATOR_H_
#define _MUTATOR_H_

#include "lazy.h"

namespace fuzzer {

namespace runtime {

///
/// \class  Mutator
///
class Mutator : public LazyEvaluation
{
public:
    ///
    /// \brief  Mutate to next form
    ///
    virtual bool mutate() = 0;

    ///
    /// \brief  Indicates if the mutator is done or not.
    ///
    virtual bool finished() = 0;

    ///
    /// \brief  Resets the mutator to it's initial state
    ///
    virtual void reset() = 0;
};

} // namespace runtime

} // namespace fuzzer

#endif