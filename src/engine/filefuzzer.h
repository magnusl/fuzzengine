#ifndef _FILEFUZZER_H_
#define _FILEFUZZER_H_

#include "appexec.h"

namespace fuzzer {

namespace runtime {

///
/// \brief
///
class FileFuzzer
{
public:
    ///
    /// \brief  Constructor
    ///
    FileFuzzer(execution::IApplicationExecuter &);

    ///
    /// \brief  Destructor
    ///
    virtual ~FileFuzzer();

    ///
    /// \brief  Runs the fuzz testing on a single file
    ///
    bool Run(const char * filename, int timeout = 5000);

private:
    execution::IApplicationExecuter & _executer;    //< executes the actual application
};

} // namespace runtime

} // namespace fuzzer

#endif