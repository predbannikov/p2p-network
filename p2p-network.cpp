#include <iostream>
#include <boost/asio/io_service.hpp>
#include <boost/asio.hpp>
#include <boost/thread/thread.hpp>

using namespace boost::asio;

typedef boost::shared_ptr<boost::asio::ip::tcp::socket> socket_ptr;

void client_session(socket_ptr sock);

int main(int argc, char *argv[]) {
    std::cout << "Path: " << argv[0] << std::endl;
    boost::asio::io_service service;
    boost::asio::ip::tcp::endpoint ep(boost::asio::ip::tcp::v4(), 2001);
    boost::asio::ip::tcp::acceptor acc(service, ep);
    while(true) {
        socket_ptr sock(new boost::asio::ip::tcp::socket(service));
        acc.accept(*sock);
        boost::thread( boost::bind(client_session, sock));
        std::cout << "new connection: " << std::endl;
    }


    return 0;
}

void client_session(socket_ptr sock)
{
    std::cout << "client session open" << std::endl;
    boost::system::error_code error;
    while(true) {
        char data[512];
        size_t len = sock->read_some(boost::asio::buffer(data), error);
        if (error == error::eof) 
            return ; // Connection refused
        if (len > 0)
            write(*sock, boost::asio::buffer("ok", 2));
        std::cout << "iteration ended" << std::endl;
    }
}

