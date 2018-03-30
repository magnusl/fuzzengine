#ifndef _IOERROR_H_
#define _IOERROR_H_

#include <stdexcept>

namespace fuzzer {

namespace io {

///
/// \class  IoException
///
class IoException : public std::runtime_error
{
public:
    IoException(const char * Message) : std::runtime_error(Message)
    {
    }
};

}

}


#endif