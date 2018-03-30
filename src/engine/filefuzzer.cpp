#include "filefuzzer.h"
#include "filemutator.h"
#include "buffer.h"
#include "tmpfile.h"
#include <iostream>

namespace fuzzer {

namespace runtime {

FileFuzzer::FileFuzzer(execution::IApplicationExecuter & executer) :
    _executer(executer)
{
}

FileFuzzer::~FileFuzzer()
{
    // empty
}

bool FileFuzzer::Run(const char * filename, int timeout)
{
    FileMutator mutator(filename);
    while(!mutator.finished())
    {
        if (!mutator.mutate()) {
            return false;
        }
        std::vector<uint8_t> payload;   //< fuzzed payload
        Buffer buffer(payload);         //< wrapper
        mutator.evaluate(buffer);       //< create fuzzed payload

        /// now save the payload to a temporary file
        fuzzer::TmpFile tmpfile(payload, filename);

        /// pass the filename as argument to the program under test
        _executer.SetCommandLine(tmpfile.filename());

        if (!_executer.Launch()) {
            std::cerr << "failed to launch \"" << filename << "\"" << std::endl;
            return false;
        }

        if (!_executer.Wait(timeout)) {
            // process didn't terminate within the timeout period
            if (!_executer.Terminate()) {
                std::cerr << "failed to terminate process." << std::endl;
                return false;
            }
            // we killed the process
        } else {
            // the process terminated
            int code;
            execution::TerminationReason reason;
            if (!_executer.GetStatusCode(code, reason)) {
                std::cerr << "Failed to get status code." << std::endl;
                return false;
            }
            if (reason != execution::Term_Normal) {
                std::string state;
                if (!mutator.state(state)) {
                    std::cerr << "failed to get mutator state." << std::endl;
                    return false;
                }
                std::cout << "crash in \"" << filename << "\" state = {" << state << "}" << std::endl;
            }
        }
    }
    return true;
}

} // namespace runtime

} // namespace fuzzer
