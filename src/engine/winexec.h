#ifndef _WINEXEC_H_
#define _WINEXEC_H_

#ifdef WIN32

#include "appexec.h"
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string>

namespace fuzzer {

namespace execution {

///
/// \brief  Executes a Windows application
///
class WindowsExecuter : public IApplicationExecuter
{
public:
    WindowsExecuter(const std::string & Path);

    ///
    /// \brief  Destructor
    ///
    ~WindowsExecuter();

    ///
    /// \brief  Sets the command line that should be passed to the application
    ///
    virtual void SetCommandLine(const std::string &);

    ///
    /// \brief  Launches the application
    ///
    virtual bool Launch();

    ///
    /// \brief  Terminate the application if it is currently running.
    ///
    virtual bool Terminate();

    ///
    /// \brief  Get the status code of the application
    ///
    virtual bool GetStatusCode(int & StatusCode, TerminationReason & Reason);

    ///
    /// \brief  Wait for the application to terminate.
    ///
    /// \param [in] TimeOut     The maximum time to wait for the application
    ///                         to terminate.
    ///
    virtual bool Wait(int TimeOut);

    ///
    /// \brief  Returns the current application status running status.
    ///
    /// \return true if the application is currently running, or false if it
    ///         has terminated.
    ///
    virtual bool IsAlive();

private:
    std::string             _path;
    STARTUPINFOA            _si;
    PROCESS_INFORMATION     _pi;
    std::string             _cmdline;
};

} // namespace execution

} // namespace fuzzer

#endif // WIN32
#endif // _WINEXEC_H_
