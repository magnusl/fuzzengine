#ifndef _TMPFILE_H_
#define _TMPFILE_H_

#include <vector>
#include <stdint.h>

namespace fuzzer {

///
/// \class  TmpFile
///
class TmpFile
{
public:
    TmpFile(const std::vector<uint8_t> & payload,
        const char * Template);

    virtual ~TmpFile();

    const std::string & filename() const { return _filename; }

protected:
    std::string     _filename;
};

} // namespace fuzzer

#endif
