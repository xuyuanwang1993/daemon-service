#include "unix-socket-helper.h"
#include <fcntl.h>
using namespace aimy;
/********************************unix_socket_base**********************************/
unix_socket_base::unix_socket_base(const string &path):m_fd(INVALID_SOCKET)
{
    m_path[PATH_MAX_SIZE]='\0';
    strncpy(m_path,path.c_str(),PATH_MAX_SIZE);
}

unix_socket_base::~unix_socket_base(){
    if(m_fd!=INVALID_SOCKET)::close(m_fd);
    if(m_path[0]!='\0')unlink(m_path);
}

ssize_t unix_socket_base::recv(void *buf, uint32_t max_len, uint32_t timeout_msec)
{
    if (timeout_msec > 0)
    {
        int flags = fcntl(m_fd, F_GETFL, 0);
        fcntl(m_fd, F_SETFL, flags | O_NONBLOCK);
        fd_set fdRead;
        FD_ZERO(&fdRead);
        FD_SET(m_fd, &fdRead);
        struct timeval tv = { static_cast<__time_t>(timeout_msec / 1000), static_cast<__suseconds_t>(timeout_msec % 1000 * 1000 )};
        select(m_fd + 1, &fdRead, nullptr, nullptr, &tv);
        if (FD_ISSET(m_fd, &fdRead))
        {
            return ::read(m_fd,buf,max_len);
        }
        else {
            return -1;
        }
    }
    else {
        return ::read(m_fd,buf,max_len);
    }

}
/********************************unix_stream_socket**********************************/
unix_stream_socket::unix_stream_socket(const string &path):unix_socket_base(path)
{

}
SOCKET unix_stream_socket::build(){
    SOCKET fd=socket(PF_UNIX,SOCK_STREAM,0);
    string path(m_path);
    if(!path.empty()&&fd!=INVALID_SOCKET)
    {
        sockaddr_un addr;
        addr.sun_family=AF_UNIX;
        strncpy(addr.sun_path,path.c_str(),108);
        unlink(addr.sun_path);
        auto ret =::bind(fd,reinterpret_cast<sockaddr *>(&addr),sizeof (addr));
        if(ret!=0)
        {
            ::close(fd);
            fd=INVALID_SOCKET;
        }
    }
    m_fd=fd;
    return m_fd;
}
void unix_stream_socket::reset(SOCKET fd,const string & path)
{
    if(m_path[0]!='\0')unlink(m_path);
    if(m_fd!=INVALID_SOCKET)::close(m_fd);
    m_fd=fd;
    strncpy(m_path,path.c_str(),PATH_MAX_SIZE);
}
ssize_t unix_stream_socket::send(const void *buf,uint32_t len,const string &/*peer_path*/)
{
    if(len==0)return 0;
    return ::write(m_fd,buf,len);
}

bool unix_stream_socket::listen(int32_t size)
{
    return ::listen(m_fd,size)==0;
}
bool unix_stream_socket::connect(const string &server_path)
{
    sockaddr_un server_addr;
    server_addr.sun_family=AF_UNIX;
    strncpy(server_addr.sun_path,server_path.c_str(),PATH_MAX_SIZE);
    return ::connect(m_fd,reinterpret_cast<sockaddr *>(&server_addr),sizeof (server_addr))==0;
}
SOCKET unix_stream_socket::aacept()
{
    return ::accept(m_fd,nullptr,nullptr);
}
/********************************unix_dgram_socket**********************************/
unix_dgram_socket::unix_dgram_socket(const string &path):unix_socket_base (path)
{
    memset(&m_peer_path,'\0',sizeof (m_peer_path));
    m_peer_path.sun_family=AF_UNIX;
}
SOCKET unix_dgram_socket::build()
{
    SOCKET fd=socket(PF_UNIX,SOCK_DGRAM,0);
    string path(m_path);
    if(!path.empty()&&fd!=INVALID_SOCKET)
    {
        sockaddr_un addr;
        addr.sun_family=AF_UNIX;
        strncpy(addr.sun_path,path.c_str(),108);
        unlink(addr.sun_path);
        auto ret =::bind(fd,reinterpret_cast<sockaddr *>(&addr),sizeof (addr));
        if(ret!=0)
        {
            ::close(fd);
            fd=INVALID_SOCKET;
        }
    }
    m_fd=fd;
    return m_fd;
}
ssize_t unix_dgram_socket::send(const void *buf,uint32_t len,const string &peer_path)
{
    if(len==0)return 0;
    if(!peer_path.empty())
    {
        sockaddr_un destination;
        destination.sun_family=AF_UNIX;
        strncpy(destination.sun_path,peer_path.c_str(),PATH_MAX_SIZE);
        return :: sendto(m_fd,buf,len,0,reinterpret_cast<sockaddr *>(&destination),sizeof (destination));
    }
    else {
        return ::sendto(m_fd,buf,len,0,reinterpret_cast<sockaddr *>(&m_peer_path),sizeof (m_peer_path));
    }
}
