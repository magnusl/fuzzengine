#ifndef _TCP_H_
#define _TCP_H_

#include <stdint.h>
#include <string>

#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinSock2.h>
#endif

#include <memory>
#include "io.h"

namespace fuzzer {

namespace network {

#ifdef WIN32
    typedef SOCKET Socket_t;
#else
    typedef int Socket_t;
#endif

///
/// \brief  Socket which can be read from and written to.
///
class TcpSocket : public io::Ipc
{
public:
    ///
    /// \brief  Constructor, initializes the instance
    ///
    explicit TcpSocket(Socket_t);
    
    ///
    /// \brief  Destructor, performs the required cleanup
    ///
    ~TcpSocket();

    ///
    /// \brief   Write data to the remote peer.
    ///
    virtual bool write(const void * Source, size_t count);

    ///
    /// \brief  Read data from the remote peer.
    ///
    virtual bool read(void * Dst, size_t count);

private:
    Socket_t _sock;
    size_t      _timeout;
};

///
/// \brief  TCP server that binds to a interface and port
///
class TcpServer
{
public:
    ///
    /// \brief  Binds the TCP server to the port on the interface
    ///
    /// \param [in] Interface   The interface to bind on.
    /// \param [in] port        The port to bind to
    ///
    TcpServer(const std::string & Interface, uint16_t port);

    ///
    /// \brief  Destructor, performs the required cleanup
    ///
    virtual ~TcpServer();

    ///
    /// \brief  Accepts a incoming connection.
    ///
    /// \param [in] TimeOut     Operation timeout in ms.
    ///
    /// \return     A TcpSocket for the connected client, or nullptr on timeout
    ///             or error.
    ///
    std::shared_ptr<TcpSocket> Accept(size_t TimeOut);

private:
    Socket_t    _sock;
};

} // namespace network

} // namespace fuzzer

#endif