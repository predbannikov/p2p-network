#include <boost/json/error.hpp>
#include <iostream>
#include <string>
#include <fstream>
#include <boost/asio/io_service.hpp>
#include <boost/asio.hpp>
#include <boost/thread/thread.hpp>
#include <boost/json/src.hpp>

using namespace boost::asio;

#define PATH_JSON   "map_address"
#define SIGNAL_SERVER   "45.128.207.31"
#define PORT_LISTEN     "2021"

typedef boost::shared_ptr<boost::asio::ip::tcp::socket> socket_ptr;

void client_session(socket_ptr sock);

std::string get_string_myip() {
    boost::asio::io_service service;
    boost::asio::ip::udp::resolver resolver(service);
    boost::asio::ip::udp::resolver::query query(boost::asio::ip::udp::v4(), "google.com", "");
    boost::asio::ip::udp::resolver::iterator iter = resolver.resolve(query);
    boost::asio::ip::udp::endpoint eptest = *iter;
    boost::asio::ip::udp::socket sock(service);
    sock.connect(eptest);
    std::string string_ip = sock.local_endpoint().address().to_string();
    std::cout << string_ip << std::endl;
    return string_ip;
}


boost::json::value load_json() {
        std::ifstream file(PATH_JSON);
        if (!file.is_open()) {
                std::cerr << "could not open file to read " << PATH_JSON << std::endl;
                exit(EXIT_FAILURE);
        }
        std::string* pstr = new std::string(std::istream_iterator<char>(file), std::istream_iterator<char>());
        boost::json::value value = boost::json::parse(*pstr);
        file.close();
        return value;
}

void save_json(boost::json::object &jobj) {
    std::ofstream file(PATH_JSON);
    if(!file.is_open()) {
        std::cerr << "could not open file to write " << PATH_JSON << std::endl;
        exit(EXIT_FAILURE);
    }
    std::string str_buf = boost::json::serialize(jobj);
    file.write(str_buf.c_str(), str_buf.length());
    file.close();
}



int main(int argc, char *argv[]) {

    std::string my_ip = get_string_myip();

    if(my_ip == SIGNAL_SERVER) {

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

    } else {

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
        boost::asio::ip::tcp::endpoint ep = sock->remote_endpoint();
        std::cout << "address " << ep.address().to_string() << std::endl;
        std::cout << "port " << ep.port() << std::endl;
        std::cout << "iteration ended" << std::endl;

    }
}

