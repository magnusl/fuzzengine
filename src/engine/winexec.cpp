#include "winexec.h"
#include <locale>
#include <codecvt>
#include <sstream>

namespace fuzzer {

namespace execution {


WindowsExecuter::WindowsExecuter(const std::string & Path) : _path(Path)
{
    ZeroMemory(&this->_pi, sizeof(PROCESS_INFORMATION));
    ZeroMemory(&this->_si, sizeof(STARTUPINFO));
}

WindowsExecuter::~WindowsExecuter()
{
    Terminate();
    Wait(-1);
    CloseHandle( _pi.hProcess );
    CloseHandle( _pi.hThread );
}

void WindowsExecuter::SetCommandLine(const std::string & cmd)
{
    _cmdline = cmd;
}

bool WindowsExecuter::Launch()
{
    /// Prevent Windows from showing a crash dialog
    SetErrorMode(
        SEM_FAILCRITICALERRORS |
        SEM_NOALIGNMENTFAULTEXCEPT |
        SEM_NOGPFAULTERRORBOX |
        SEM_NOOPENFILEERRORBOX
        );

    if (_path.empty()) {
        return false;
    }

    /// perform cleanup if instance is reused.
    if (_pi.hProcess) {
        CloseHandle( _pi.hProcess );
        ZeroMemory(&this->_pi, sizeof(PROCESS_INFORMATION));
        CloseHandle( _pi.hThread );
        ZeroMemory(&this->_si, sizeof(STARTUPINFO));
    }


    std::stringstream ss;
    ss << _path;
    if (!_cmdline.empty()) {
        ss << " " << _cmdline;
    }

    if (!CreateProcessA(_path.c_str(), 
        (LPSTR) ss.str().c_str(),
        NULL,
        NULL,
        FALSE,
        0,
        NULL,
        NULL,
        &_si,
        &_pi))
    {
        return false;
    }

    return true;
}

bool WindowsExecuter::Terminate()
{
    if (!_pi.hProcess) {
        return false;
    }
    if (!TerminateProcess(_pi.hProcess, 0)) {
        return false;
    }
    return true;
}

bool WindowsExecuter::Wait(int TimeOut)
{
    if (!_pi.hProcess) {
        return false;
    }
    DWORD res = WaitForSingleObject(_pi.hProcess, TimeOut > 0 ? TimeOut : INFINITE);
    if (res == WAIT_OBJECT_0) {
        return true;
    } else {
        return false;
    }
}

bool WindowsExecuter::IsAlive()
{
    if (!_pi.hProcess) {
        return false;
    }
    DWORD status;
    if (GetExitCodeProcess(_pi.hProcess, &status)) {
        if (status == STILL_ACTIVE) {
            return true;
        }
    }
    return false;
}

bool WindowsExecuter::GetStatusCode(int & StatusCode, TerminationReason & Reason)
{
    if (IsAlive()) {
        return false;
    }

    DWORD status;
    if (GetExitCodeProcess(_pi.hProcess, &status)) {
        if (status != STILL_ACTIVE) {
            StatusCode = static_cast<int>(status);

            switch(status) {
            case EXCEPTION_ACCESS_VIOLATION:        Reason = Term_SegmentationFault; break;
            case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:   Reason = Term_BoundsError; break;
            case EXCEPTION_DATATYPE_MISALIGNMENT:   Reason = Term_UnalignedAccess; break;
            case EXCEPTION_STACK_OVERFLOW:          Reason = Term_StackOverflow; break;
            default:                                Reason = Term_Other; break;
            }
            return true;
        }
    }
    return false;
}

} // namespace execution

} // namespace fuzzer