#ifndef _INTEGERMUTATOR_H_
#define _INTEGERMUTATOR_H_

#include "mutator.h"
#include "buffer.h"

namespace fuzzer {

namespace runtime {

///
/// \class  UnsignedMutator
/// \brief  Mutator for unsigned integers
///
template<class T>
class UnsignedMutator : public Mutator
{
public:
    UnsignedMutator(
        T InitialValue, 
        T Low = std::numeric_limits<T>::min(), 
        T Upper = std::numeric_limits<T>::max()) : 
        _current(InitialValue), _initial(InitialValue), _lower(Low), _upper(Upper)
    {
    }

    virtual bool mutate()
    {
        _current += 1;
        return true;
    }

    virtual bool finished()
    {
        return false;
    }

    virtual void evaluate(Buffer & buf)
    {
        switch(sizeof(T)) {
        case 1: buf.writeU8(static_cast<uint8_t>(_current)); break;
        case 2: buf.writeU16(static_cast<uint16_t>(_current)); break;
        case 4: buf.writeU32(static_cast<uint32_t>(_current)); break;
        case 8: buf.writeU64(static_cast<uint64_t>(_current)); break;
        default:
            throw std::runtime_error("Incorrect type.");
        }
    }

    virtual void reset()
    {
    }

    T current() const { return _current; }

private:
    T   _initial;
    T   _lower;
    T   _upper;
    T   _current;
};

} // namespace runtime

} // namespace fuzzy

#endif