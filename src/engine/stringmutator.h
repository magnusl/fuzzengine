#ifndef _STRINGMUTATOR_H_
#define _STRINGMUTATOR_H_

#include "mutator.h"

namespace fuzzer {

namespace runtime {

class StringMutator : public Mutator
{
public:
    StringMutator(const char * str);

protected:
    bool NextString(std::string &);
    bool HasMore();

private:
    void repeat(const char *, size_t count);

protected:
    std::string                 _initial;
    std::vector<std::string>    _db;
    size_t                      _index;
};

///
/// \class  AsciiStringMutator
/// \brief  Mutator for ASCII strings
///
class AsciiStringMutator : public StringMutator
{
public:
    enum Representation {
        LINE,
        CSTRING,
        PASCAL8,
        PASCAL16,
        PASCAL32,
        PASCAL64
    };

    AsciiStringMutator(Representation representation, const char * Initial) :
        StringMutator(Initial),
        _representation(representation)
    {
        NextString(_current);
    }

    virtual bool mutate()
    {
        return NextString(_current);
    }

    virtual bool finished() { return !HasMore(); }

    virtual void reset() { _index = 0; }

    virtual void evaluate(Buffer & buffer)
    {
        switch(_representation) {
        case CSTRING:
            /// write the string plus the NULL terminator
            buffer.write(_current.c_str(), _current.size() + 1);
            break;
        case LINE:
            buffer.write(_current.c_str(), _current.size() + 1);
            buffer.write("\r\n", 2);
            break;
        default:
            break;
        }
    }
    
protected:
    Representation  _representation;
    std::string     _current;
};

///
/// \class  Utf8StringMutator
/// \brief  Mutator for UTF-8 strings
///
class Utf8StringMutator : public Mutator
{
public:

};

} // namespace runtime

} // namespace fuzzer

#endif