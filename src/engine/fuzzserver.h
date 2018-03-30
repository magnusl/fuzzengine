#ifndef _FUZZSERVER_H_
#define _FUZZSERVER_H_

#include "fuzzer.h"
#include "tcp.h"
#include "appexec.h"
#include "script.h"
#include <memory>

namespace fuzzer {

namespace runtime {

///
/// \class FuzzServer
/// \brief Server side for fuzzing clients.
///
class FuzzServer : public Fuzzer
{
public:
    ///
    /// \brief  Constructor
    ///
    FuzzServer(network::TcpServer &, execution::IApplicationExecuter &);

    ///
    /// \brief  Performs the fuzzing
    ///
    void Run(const bytecode::Script &, size_t ConnectTimeout);

private:
    
    std::shared_ptr<network::TcpSocket> WaitForIncoming(size_t Timeout);

    network::TcpServer &                _network;
    execution::IApplicationExecuter &   _app;
};

} // namespace runtime

} // namespace  fuzzer

#endif