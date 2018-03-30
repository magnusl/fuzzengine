#ifndef _FILEMUTATOR_H_
#define _FILEMUTATOR_H_

#include "mutator.h"

namespace fuzzer {

namespace runtime {

///
/// \brief  Mutates files
///
class FileMutator : public Mutator
{
public:
    ///
    /// \brief  Constructor
    ///
    /// \param [in] filename    The file to mutate. The file will not be modified.
    ///
    FileMutator(const char * filename);

    ///
    /// \brief  Destructor
    ///
    virtual ~FileMutator();

    ///
    /// \brief  Mutate to next form
    ///
    virtual bool mutate();

    ///
    /// \brief  Indicates if the mutator is done or not.
    ///
    virtual bool finished();

    ///
    /// \brief  Resets the mutator to it's initial state
    ///
    virtual void reset();

    ///
    /// \brief  Unsupported
    ///
    virtual void evaluate(Buffer &);

    ///
    /// \brief
    ///
    virtual bool state(std::string &);

protected:
    enum Phase {
        BIT_INVERSE,    //< inverse each bit
        BYTE_REMOVAL,   //< remove byte
        DONE,           //< fuzzing done
    };

protected:

    std::vector<uint8_t>    _data;      //< original file data
    std::string             _name;      //< file name
    Phase                   _phase;     //< current phase
    size_t                  _offset;    //< current offset
};

} // namespace runtime

} // namespace fuzzer

#endif