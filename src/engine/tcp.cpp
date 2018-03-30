#include "tcp.h"
#include "ioerror.h"
#include <stdexcept>
#include <sstream>

#ifdef WIN32
#include <ws2tcpip.h>
#endif

#include <limits>

using namespace std;

namespace fuzzer {

namespace network {

///
/// \brief  Binds the TCP server to the port on the interface
///
/// \param [in] Interface   The interface to bind on.
/// \param [in] port        The port to bind to
///
TcpServer::TcpServer(const std::string & Interface, uint16_t port)
{
    stringstream portString;
    portString << port;

    addrinfo * result;
    if (getaddrinfo(Interface.c_str(), portString.str().c_str(), NULL, &result) != 0) {
        throw std::runtime_error("getaddrinfo failed.");
    }

    _sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (_sock == INVALID_SOCKET) {
        freeaddrinfo(result);
        throw std::runtime_error("Failed to create socket.");
    }
#ifdef WIN32
    unsigned long mode = 1;
    if (ioctlsocket(_sock, FIONBIO, &mode) != 0) {
        freeaddrinfo(result);
        closesocket(_sock);
        throw std::runtime_error("Failed to set non-blocking mode.");
    }
#else
#error "Support for non-blocking sockets not supported"
#endif

    if (bind(_sock, result->ai_addr, (int)result->ai_addrlen) < 0) {
        freeaddrinfo(result);
        closesocket(_sock);
        throw std::runtime_error("Failed to bind.");
    }

    freeaddrinfo(result);

    if (listen(_sock, SOMAXCONN) < 0) {
        closesocket(_sock);
        throw std::runtime_error("Failed to listen.");
    }
}

///
/// \brief  Destructor, performs the required cleanup
///
TcpServer::~TcpServer()
{
#ifdef WIN32
    closesocket(_sock);
#else
    close(_sock);
#endif
}

std::shared_ptr<TcpSocket> TcpServer::Accept(size_t TimeOut)
{
    fd_set set;
    FD_ZERO(&set);
    FD_SET(_sock, &set);

    timeval tv;
    tv.tv_sec   = 0;
    tv.tv_usec  = TimeOut * 1000;

    if (select(0, &set, NULL, NULL, &tv) < 0) {
        return nullptr;
    }

    Socket_t sock = accept(_sock, NULL, NULL);
    if (sock == ((Socket_t) -1)) {
        return nullptr;
    }
    return make_shared<TcpSocket>(sock);
}

///////////////////////////////////////////////////////////////////////////////
//                                      TcpSocket                            //
///////////////////////////////////////////////////////////////////////////////

///
/// \brief  Constructor, initializes the instance
///
TcpSocket::TcpSocket(Socket_t sock) : _sock(sock), _timeout(2000)
{
}
    
///
/// \brief  Destructor, performs the required cleanup
///
TcpSocket::~TcpSocket()
{
#ifdef WIN32
    closesocket(_sock);
#else
    close(_sock);
#endif
}

///
/// \brief   Write data to the remote peer.
///
bool TcpSocket::write(const void * Source, size_t count)
{
    const char * ptr = static_cast<const char*>(Source);
    
    while(count > 0) {
        int len = (count > INT_MAX ? INT_MAX : count);
        int res = send(_sock, ptr, len, 0);
        if (res < 0) {
#ifdef WIN32
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) {
                continue;
            }
            return false;
#else
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                continue;
            }
            return false;
#endif
        } else {
            if (static_cast<size_t>(res) > count) { /// sanity test
                return false;
            }
            count   -= res;
            ptr     += res;
        }
    }
    return true;
}

///
/// \brief  Read data from the remote peer.
///
bool TcpSocket::read(void * Dst, size_t count)
{
    DWORD start = GetTickCount();
    char * ptr = static_cast<char*>(Dst);
    while(count) {
        int res = recv(_sock, ptr, count, 0);
        if (res == 0) {
            return false;
        } else if (res < 0) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) {
                if ((GetTickCount() - start) > _timeout) {
                    throw io::IoException("Read operation timed out.");
                }
                continue;
            }
            return false;
        } else {
            count   -= res;
            ptr     += res;
        }
    }
    return true;
}

} // namespace network

} // namespace fuzzer
