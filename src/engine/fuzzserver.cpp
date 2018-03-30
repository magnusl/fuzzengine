#include "fuzzserver.h"
#include "ioerror.h"
#include <iostream>

using namespace std;

namespace fuzzer {

namespace runtime {

///
/// \brief  Constructor
///
FuzzServer::FuzzServer(
    network::TcpServer & network, execution::IApplicationExecuter & app) :
    _network(network),
    _app(app)
{
}

shared_ptr<network::TcpSocket> FuzzServer::WaitForIncoming(size_t Timeout)
{
    static const size_t interval = 25;
    for(size_t time = 0; time < Timeout; time += interval) {
        if (!_app.IsAlive()) {
            return nullptr;
        }
        shared_ptr<network::TcpSocket> sock = _network.Accept(interval);
        if (sock) {
            return sock;
        }
    }
    return nullptr;
}

const char * TerminationReason(int Code)
{
    switch(Code) {
    case EXCEPTION_ACCESS_VIOLATION:
        return "access violation";
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
        return "array bounds exceeded";
    case EXCEPTION_DATATYPE_MISALIGNMENT:
        return "misaligned data access";
    case EXCEPTION_STACK_OVERFLOW:
        return "stack overflow.";
    default:
        return "unknown";
    }
}

///
/// \brief  Performs the fuzzing
///
void FuzzServer::Run(const bytecode::Script & script,
    size_t ConnectTimeout)
{
    /// For each template
    for(map<string, shared_ptr<Template> >::const_iterator it = script._templates.begin();
        it != script._templates.end();
        it++)
    {
        /// For each mutator
        vector<runtime::Mutator *> mutators = it->second->GetMutators();
        for(size_t i = 0; i < mutators.size(); ++i) {
            if (runtime::Mutator * mutator = mutators[i]) {
                /// For each mutation
                mutator->reset();
                do {
                    /// Launch the application so that it can connect to the server
                    if (!_app.Launch()) {
                        /// failed to launch application, throw exception
                        std::cout << "Failed to launch application." << std::endl;
                    }
                    /// Wait for a incoming connection
                    shared_ptr<network::TcpSocket> sock = WaitForIncoming(ConnectTimeout);
                    if (!sock) {
                        /// no incoming connection, terminate the application and report the issue
                        _app.Terminate();
                        _app.Wait();
                    } else {
                        /// We have a incoming connection, use this as IPC between the fuzzer and
                        /// the launched application.
                        this->_ipc = sock.get();

                        try {
                            _vm.Execute( script );
                            _app.Terminate();
                            _app.Wait();
                            /// The script finished execution
                            int statusCode;
                            execution::TerminationReason reason;
                            _app.GetStatusCode(statusCode, reason);
                            std::cout << "App exited with " << statusCode << ", " << TerminationReason(statusCode) << std::endl;
                        } catch(io::IoException & err) {
                            /// error while communicating with peer
                            std::cout << "Caught I/O exception: " << err.what() << std::endl;
                        } catch(std::runtime_error & err) {
                            std::cout << "Caught runtime error: " << err.what() << std::endl;
                        } catch(...) {
                            /// caught an exception while executing the script
                            std::cout << "Caught unknown exception." << std::endl;
                        }
                        _app.Terminate();
                        _app.Wait();
                        int statusCode;
                        execution::TerminationReason reason;
                        _app.GetStatusCode(statusCode, reason);
                    }
                    /// continue with next mutation
                    mutator->mutate();
                } while(!mutator->finished());

                std::cout << "Mutator is done." << std::endl;
            }
        }
    }
}

} // namespace runtime

} // namespace fuzzer