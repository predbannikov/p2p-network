#include <boost/json/error.hpp>
#include <iostream>
#include <string>
#include <fstream>
#include <boost/asio/io_service.hpp>
#include <boost/asio.hpp>
#include <boost/thread/thread.hpp>
#include <boost/json/src.hpp>
#include <mutex>
#include <thread>

using namespace boost::asio;

#define PATH_JSON   "map-address"
//#define SIGNAL_SERVER   "45.128.207.31"
#define SIGNAL_SERVER   "192.168.0.101"
#define SERVER_PORT     2001

typedef boost::shared_ptr<boost::asio::ip::tcp::socket> socket_ptr;

std::mutex mtx_rwfile;

void client_session(socket_ptr sock);

std::string get_string_myip() {
    std::cout  << "getting my ip" << std::endl;
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
    std::lock_guard<std::mutex> lock();
    std::ifstream file(PATH_JSON);
    if (!file.is_open()) {
        std::cerr << "could not open file to read " << PATH_JSON << std::endl;
        return boost::json::value();
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

void added_new_machine(std::string ip_str) {
    boost::json::object jobj;
    jobj.emplace("ip", ip_str);
    std::cout << jobj << std::endl;
    save_json(jobj);
}
 
void server(boost::asio::io_service& io_service, unsigned short port)
{
    enum {max_length = 1024};
    boost::asio::ip::udp::socket sock(io_service, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), port));
    for (;;)
    {
        char data[max_length];
        boost::asio::ip::udp::endpoint sender_endpoint;
        std::cout << "start server on: " << sock.local_endpoint() << " mustbe=" << port << std::endl;
        size_t length = sock.receive_from(boost::asio::buffer(data, 1024), sender_endpoint);
        std::cout << "data: "  << data << " " << sender_endpoint << std::endl;
        sock.send_to(boost::asio::buffer(data, length), sender_endpoint);
    }
}

int main(int argc, char *argv[]) {

    std::cout << "start programm" << std::endl;
    std::cout << "load: " << load_json() << std::endl;
    std::string my_ip = get_string_myip();
    added_new_machine(my_ip);

    if(my_ip == SIGNAL_SERVER) {

        boost::asio::io_service service;
        boost::asio::ip::tcp::endpoint ep(boost::asio::ip::tcp::v4(), SERVER_PORT);
        boost::asio::ip::tcp::acceptor acc(service, ep);
        while(true) {
            socket_ptr sock(new boost::asio::ip::tcp::socket(service));
            acc.accept(*sock);
            boost::thread( boost::bind(client_session, sock));
            std::cout << "new connection: " << std::endl;
        }

    } else {
        char buff[1024];
        boost::asio::io_service service;
        socket_ptr sock(new boost::asio::ip::tcp::socket(service));
        boost::asio::ip::tcp::endpoint ep_server(boost::asio::ip::address::from_string(SIGNAL_SERVER), 2001);
        sock->connect(ep_server);
        sock->read_some(boost::asio::buffer(buff));
        sock->set_option(boost::asio::ip::tcp::socket::reuse_address(true));

        while(true) {
            boost::asio::io_service io_service;
            std::string sport = std::string(buff);
            std::cout << "port: " << sport << std::endl;
            int p = std::stoi(sport);
            std::cout << "p = " << p << std::endl;
            server(io_service, p);
            //std::string msg;
            //std::cin >> msg;
            //sock->write_some(buffer(msg.c_str(), msg.length()));
//            socket_ptr sock_2(new boost::asio::ip::tcp::socket(service));
//            boost::asio::ip::tcp::acceptor acc(service, sock->local_endpoint());
//            acc.listen();
//            acc.accept(*sock_2);
//            std::cout << sock->remote_endpoint() << std::endl;
//            std::cout << "receive message:" << std::endl;
//            sock_2->receive(boost::asio::buffer(buff));
//            std::cout << buff << std::endl;
        }

    }    
    return 0;
}

void client_session(socket_ptr sock)
{
    std::cout << "***   client session open   ***" << std::endl;
    boost::asio::ip::tcp::endpoint ep = sock->remote_endpoint();
    boost::json::object jobj = {
        { "ip", ep.address().to_string() },
        { "port", ep.port() }
    };
    save_json(jobj);

    std::cout << ep << std::endl;
    std::string port = std::to_string(ep.port());
    std::cout << "send port: " << port << std::endl;
    sock->write_some(boost::asio::buffer(port.c_str(), port.length()));
    boost::system::error_code error;
    try {

        while(true) {
            char data[512];
            sock->receive(boost::asio::buffer(data));
            if (error) {
                std::cout << error.message() << std::endl;
                break; // Connection refused
            }
            std::cout << "ok: " << data << std::endl;

        }
    }
    catch(...) {
        std::cout << "catch exception" << error.message() << std::endl;
    }
    std::cout << "iteration ended" << std::endl;
}

