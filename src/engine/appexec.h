#ifndef _APPEXEC_H_
#define _APPEXEC_H_

#include <string>

namespace fuzzer {

namespace execution {

enum TerminationReason {
    Term_Normal,
    Term_SegmentationFault, 
    Term_BoundsError,
    Term_UnalignedAccess,
    Term_StackOverflow,
    Term_Other
};

///
/// \brief  Interface for launch and control an application.
///
class IApplicationExecuter
{
public:
    ///
    /// \brief  Virtual destructor
    ///
    virtual ~IApplicationExecuter()
    {
        // empty
    }

    ///
    /// \brief  Launches the application
    ///
    virtual bool Launch() = 0;

    ///
    /// \brief  Terminate the application if it is currently running.
    ///
    virtual bool Terminate() = 0;

    ///
    /// \brief  Get the status code of the application
    ///
    virtual bool GetStatusCode(int & StatusCode, TerminationReason & Reason) = 0;

    ///
    /// \brief  Wait for the application to terminate.
    ///
    /// \param [in] TimeOut     The maximum time to wait for the application
    ///                         to terminate.
    ///
    virtual bool Wait(int TimeOut = -1) = 0;

    ///
    /// \brief  Returns the current application status running status.
    ///
    /// \return true if the application is currently running, or false if it
    ///         has terminated.
    ///
    virtual bool IsAlive() = 0;

    ///
    /// \brief  Sets command line arguments
    ///
    virtual void SetCommandLine(const std::string &) = 0;
};

} // namespace execution

} // namespace fuzzer

#endif