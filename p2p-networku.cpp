#include <boost/asio/error.hpp>
#include <boost/json/error.hpp>
#include <boost/system/detail/error_code.hpp>
#include <iostream>
#include <string>
#include <fstream>
#include <boost/asio/io_service.hpp>
#include <boost/asio.hpp>
#include <boost/thread/thread.hpp>
#include <boost/json/src.hpp>
#include <mutex>
#include <thread>
#include "raw-to.h"

//using namespace boost::asio;

#define PATH_JSON   "map-address"
#define SIGNAL_SERVER   "45.128.207.31"
#define SERVER_PORT     2001

//typedef boost::shared_ptr<boost::asio::ip::udp::socket> socket_ptr;

std::mutex mtx_rwfile;

//void client_session(socket_ptr sock);

std::string get_string_myip() {
    boost::asio::io_service service;
    boost::asio::ip::udp::resolver resolver(service);
    boost::asio::ip::udp::resolver::query query(boost::asio::ip::udp::v4(), "google.com", "");
    boost::asio::ip::udp::resolver::iterator iter = resolver.resolve(query);
    boost::asio::ip::udp::endpoint eptest = *iter;
    boost::asio::ip::udp::socket sock(service);
    sock.connect(eptest);
    std::string string_ip = sock.local_endpoint().address().to_string();
    std::cout  << "My ip: ";
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

void server(boost::asio::io_service& io_service, short port)
{
    enum {max_length = 1024};
    boost::asio::ip::udp::socket sock(io_service, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), port));
    for (;;)
    {
        char data[max_length];
        boost::asio::ip::udp::endpoint sender_endpoint;
        std::cout << "start server on: " << sock.local_endpoint() << std::endl;
        size_t length = sock.receive_from(boost::asio::buffer(data, 1024), sender_endpoint);
        std::cout << "data: "  << data << " " << sender_endpoint << std::endl;
        sock.send_to(boost::asio::buffer(data, length), sender_endpoint);
    }
}

class UDPClient
{
public:
	UDPClient(
		boost::asio::io_service& io_service,
		const std::string& host,
		const std::string& port
	) : io_service_(io_service), socket_(io_service, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 0)) {
        boost::asio::ip::udp::resolver resolver(io_service_);
        boost::asio::ip::udp::resolver::query query(boost::asio::ip::udp::v4(), host, port);
        boost::asio::ip::udp::resolver::iterator iter = resolver.resolve(query);
		endpoint_ = *iter;
	}

	~UDPClient()
	{
		socket_.close();
	}

	void send(const std::string& msg) {
        //boost::asio::ip::udp::endpoint ep(boost::asio::ip::address::from_string("192.168.0.107"), 1111);
		socket_.send_to(boost::asio::buffer(msg, msg.size()), endpoint_);
        std::cout << "message sended " << std::endl;
        std::cout <<  socket_.local_endpoint() << std::endl;
	}

private:
	boost::asio::io_service& io_service_;
    boost::asio::ip::udp::socket socket_;
    boost::asio::ip::udp::endpoint endpoint_;
};

int main(int argc, char *argv[]) {

    std::cout << "start programm" << std::endl;
    //std::cout << "load: " << load_json() << std::endl;
    std::string my_ip = get_string_myip();
    //added_new_machine(my_ip);

    if(my_ip == SIGNAL_SERVER) {
        try {
            boost::asio::io_service io_service;
            server(io_service, 2001);
        } catch (const std::exception& ex) {
            std::cerr << ex.what() << std::endl;
        }
        //        boost::asio::io_service service;
//        boost::asio::ip::udp::endpoint ep(boost::asio::ip::udp::v4(), 2001);
//        while(true) {
//            boost::system::error_code ec = boost::asio::error::would_block;
//            std::size_t length = 0;
//            boost::asio::ip::udp::socket sock(service, ep);
//            service.run_one();
//            while(ec == boost::asio::error::would_block);
//            std::cout << "new connection: " << std::endl;
//        }

    } else {
//        boost::system::error_code ec = boost::asio::error::would_block;
//        boost::asio::io_service service;
//        boost::asio::ip::udp::resolver reslvr(service);
//        //boost::asio::ip::udp::resolver::query query(boost::asio::ip::udp::v4(), SIGNAL_SERVER, 2001);
//        boost::asio::ip::udp::endpoint ep_server(boost::asio::ip::address::from_string(SIGNAL_SERVER), 2001);
//        boost::asio::ip::udp::socket sock(service);
//        sock.connect(ep_server);
//        std::cout << "try connect " << ep_server << std::endl;
        try {
            int client_server = 0;
            if(client_server) {
                boost::asio::io_service io_service;
                UDPClient client(io_service, SIGNAL_SERVER, "53272");
                client.send("hello");
            } else {
                boost::asio::io_service io_service;
                server(io_service, 50512);

            }
                        //sock.send_to(boost::asio::buffer("hello", 5), ep_server);
        }
        catch(...) {
            
            std::cout << "catch case" << std::endl;
        }
//        while(true) {
//            std::cout << sock.remote_endpoint() << std::endl;
//            std::cout << sock.local_endpoint() << std::endl;
//            char buff[1024];
//            std::size_t length = 0;
//
//            //std::string msg;
//            //std::cin >> msg;
//            //sock->write_some(buffer(msg.c_str(), msg.length()));
//            sock.set_option(boost::asio::ip::tcp::socket::reuse_address(true));
//            boost::asio::io_service service2;
//            std::cout << "case 1" << std::endl;
//            boost::asio::ip::udp::endpoint ep_ext(sock.local_endpoint().address(), sock.local_endpoint().port());
//            std::cout << "case 2" << std::endl;
//            boost::asio::ip::udp::socket sock_2(service2, ep_ext);
//            std::cout << "case 3" << std::endl;
//            sock_2.receive(boost::asio::buffer(buff));
//            service.run_one();
//            while(ec == boost::asio::error::would_block);
//
//            std::cout << "receive message:" << std::endl;
//            std::cout << buff << std::endl;
//        }

    }    
    return 0;
}

//void client_session(socket_ptr sock)
//{
//    std::cout << "***   client session open   ***" << std::endl;
//    //boost::asio::ip::tcp::endpoint ep = sock->remote_endpoint();
//    boost::json::object jobj = {
//        { "ip", ep.address().to_string() },
//        { "port", ep.port() }
//    };
//    save_json(jobj);
//
//    std::cout << ep << std::endl;
//    boost::system::error_code error;
//    try {
//
//        while(true) {
//            char data[512];
//            sock->receive(boost::asio::buffer(data));
//            if (error) {
//                std::cout << error.message() << std::endl;
//                break; // Connection refused
//            }
//            std::cout << "ok: " << data << std::endl;
//
//        }
//    }
//    catch(...) {
//        std::cout << "catch exception" << error.message() << std::endl;
//    }
//    std::cout << "iteration ended" << std::endl;
//}

