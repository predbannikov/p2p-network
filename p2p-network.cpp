#include <boost/asio/ip/address_v4.hpp>
#include <boost/json/error.hpp>
#include <boost/system/system_error.hpp>
#include <chrono>
#include <iostream>
#include <string>
#include <fstream>
#include <boost/asio/io_service.hpp>
#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <boost/thread/thread.hpp>
#include <boost/json/src.hpp>
#include <mutex>
#include <thread>

using namespace boost::asio;

#define PATH_JSON   "map-address"
#define SIGNAL_SERVER   "45.128.207.31"
//#define SIGNAL_SERVER   "192.168.0.101"
#define SERVER_PORT     2001

typedef boost::shared_ptr<boost::asio::ip::tcp::socket> socket_ptr;

std::mutex mtx_rwfile;
std::string my_ip;
boost::asio::ip::udp::endpoint server_uep(boost::asio::ip::address::from_string(SIGNAL_SERVER), SERVER_PORT);
boost::asio::ip::tcp::endpoint server_tep(boost::asio::ip::address::from_string(SIGNAL_SERVER), SERVER_PORT);
void client_session(socket_ptr sock);
void client_session_ping(socket_ptr sock, unsigned short port, int timewait);

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
 
void server(unsigned short port)
{
    std::cout << "start sync server" << std::endl;
    enum {max_length = 1024};
    boost::asio::io_service io_service;
    boost::asio::ip::udp::socket sock(io_service, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), port));
    for (;;)
    {
        if(my_ip == SIGNAL_SERVER) {
            boost::asio::ip::udp::endpoint tmp_ep(boost::asio::ip::address::from_string("178.176.159.182"), 2003);
            std::cout << "send_to " << tmp_ep  << std::endl;
            sock.send_to(boost::asio::buffer("#######", 1), tmp_ep);
        } else {
            char data[max_length];
            boost::asio::ip::udp::endpoint sender_endpoint;
            //std::cout << "start server on: " << sock.local_endpoint() << " mustbe=" << port << std::endl;
            boost::asio::ip::udp::endpoint tmp_ep(boost::asio::ip::address::from_string(SIGNAL_SERVER), 2002);
            //std::cout << "try send_to " << tmp_ep  << std::endl;
            //boost::asio::ip::udp::endpoint server_uep(boost::asio::ip::address::from_string(SIGNAL_SERVER), port);
            //sock.bind( boost::asio::ip::udp::endpoint(boost::asio::ip::address::from_string(SIGNAL_SERVER), port));

            std::cout << "send_to " << tmp_ep  << std::endl;
            sock.send_to(boost::asio::buffer("*******", 1), tmp_ep);


            //        std::cout << "try sock.receiv" << std::endl;
            //        size_t length = sock.receive_from(boost::asio::buffer(data, 1024), sender_endpoint);
            //        std::cout << "data: "  << data << " " << sender_endpoint << std::endl;
            //        sock.send_to(boost::asio::buffer(data, length), sender_endpoint);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
   }
}

class udp_server
{
    public:
        udp_server(boost::asio::io_service& io_service, int port)
            : socket_(io_service, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), port))
        {
            start_receive();
        }

    private:
        void start_receive()
        {
            socket_.async_receive_from(
                    boost::asio::buffer(recv_buffer_), remote_endpoint_,
                    boost::bind(&udp_server::handle_receive, this,
                        boost::asio::placeholders::error,
                        boost::asio::placeholders::bytes_transferred));
            std::cout << "receiv data: " << recv_buffer_.data() << std::endl;
        }

        void handle_receive(const boost::system::error_code& error,
                std::size_t /*bytes_transferred*/)
        {
            if (!error || error == boost::asio::error::message_size)
            {
                boost::shared_ptr<std::string> message(new std::string("***********"));

                socket_.async_send_to(boost::asio::buffer(*message), remote_endpoint_,
                        boost::bind(&udp_server::handle_send, this, message,
                            boost::asio::placeholders::error,
                            boost::asio::placeholders::bytes_transferred));
                std::cout << "handle_receive " << remote_endpoint_ << std::endl;
                start_receive();
            }
        }

        void handle_send(boost::shared_ptr<std::string> /*message*/,
                const boost::system::error_code& /*error*/,
                std::size_t /*bytes_transferred*/)
        {
        }

        boost::asio::ip::udp::socket socket_;
        boost::asio::ip::udp::endpoint remote_endpoint_;
        boost::array<char, 1> recv_buffer_;
};

int main(int argc, char *argv[]) {

    std::cout << "start programm" << std::endl;
    std::cout << "load: " << load_json() << std::endl;
    my_ip = get_string_myip();
    added_new_machine(my_ip);

    if(my_ip == SIGNAL_SERVER) {

//        boost::asio::io_service service;
//        boost::asio::ip::tcp::endpoint ep(boost::asio::ip::tcp::v4(), SERVER_PORT);
//        boost::asio::ip::tcp::acceptor acc(service, ep);
//        while(true) {
//            socket_ptr sock(new boost::asio::ip::tcp::socket(service));
//            acc.accept(*sock);
//            boost::thread(boost::bind(client_session, sock));
//            //boost::thread(boost::bind(client_session_ping, sock, SERVER_PORT, 3000));
                        

            boost::asio::io_service io_service;
            udp_server userv(io_service, 2002);
            boost::thread(boost::bind(server, 2003));
            io_service.run();
//            boost::thread(boost::bind(server, 2003));

//            std::cout << "new connection: " << std::endl;
//        }

    } else {
        char buff[1024];
        boost::asio::io_service service;
//        socket_ptr sock(new boost::asio::ip::tcp::socket(service));
//        boost::asio::ip::tcp::endpoint ep_server(boost::asio::ip::address::from_string(SIGNAL_SERVER), 2001);
//        sock->connect(ep_server);
//        sock->read_some(boost::asio::buffer(buff));
//        sock->set_option(boost::asio::ip::tcp::socket::reuse_address(true));
//
        udp_server userv(service, 2003);
        boost::thread(boost::bind(server, 2002));
        service.run();
//        while(true) {
//            boost::asio::io_service io_service;
//            std::string sport = std::string(buff);
//            std::cout << "port: " << sport << std::endl;
//            unsigned short p = std::stoi(sport);
//            std::cout << "p = " << p << std::endl;
//            //boost::thread(boost::bind(client_session_ping, sock, p, 1000));
//            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
//

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
//        }

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

void client_session_ping(socket_ptr sock, unsigned short port, int timewait)
{
    while(true) {
        std::cout << "################# Ping sending ############### " << std::endl;
        boost::asio::ip::tcp::endpoint ep = sock->remote_endpoint();
        boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::udp::v4(), port);
        std::cout << "ep=" << ep << std::endl;
        std::cout << "server_uep=" << server_uep << std::endl;
        std::cout << "client_ep=" << client_ep << std::endl;
        boost::asio::io_service io_service;
        boost::system::error_code ec;
        if (my_ip == SIGNAL_SERVER) {
            boost::asio::ip::udp::socket usock(io_service, server_uep);
            std::cout << "send_to " << usock.local_endpoint() << " " << client_ep << std::endl;
            std::string strsend = " #server: "; 
            usock.send_to(boost::asio::buffer(strsend.c_str(),strsend.length()), client_ep);
            
        } else {
            try {
                boost::asio::ip::udp::socket usock(io_service, client_ep);
                std::cout << "send_to " << usock.local_endpoint() << std::endl;
                std::string strsend = " #client: ";
                usock.send_to(boost::asio::buffer(strsend.c_str(),strsend.length()), server_uep);
            } 
            catch (boost::system::system_error e) {
                std::cerr << std::endl << "ERROR: " << e.what() << " " << e.what() << std::endl;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(timewait));
       
    }
   
    

}

