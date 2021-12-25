#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/placeholders.hpp>
#include <boost/json/error.hpp>
#include <boost/system/system_error.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <chrono>
#include <iostream>
#include <boost/filesystem.hpp>
#include <string>
#include <fstream>
#include <boost/asio/io_service.hpp>
#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <boost/thread/thread.hpp>
#include <boost/json/src.hpp>
#include <mutex>
#include <thread>
#include "raw-to.h"

using namespace boost::asio;

#define PATH_JSON   "map-address"
#define SIGNAL_SERVER   "45.128.207.31"
#define SERVER_PORT 50003
#define MY_MACHINE	"192.168.0.101"

typedef boost::shared_ptr<boost::asio::ip::tcp::socket> socket_ptr;
class Client;

std::mutex 	mtx_rwfile;
std::string my_ip;

boost::asio::ip::udp::endpoint server_uep(boost::asio::ip::address::from_string(SIGNAL_SERVER), SERVER_PORT);
boost::asio::ip::tcp::endpoint server_tep(boost::asio::ip::address::from_string(SIGNAL_SERVER), SERVER_PORT);

void client_session(Client*);
void client_session_ping(socket_ptr sock, unsigned short port, int timewait);
void remove_machine(std::string ip_str);


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
    return string_ip;
}

std::string load_data() {
    std::lock_guard<std::mutex> lock(mtx_rwfile);
    std::ifstream file(PATH_JSON);
    if (!file.is_open() || file.fail()) {
        std::cerr << "could not open file to read " << PATH_JSON << std::endl;
        return "";
    }
    //std::cout << boost::filesystem::current_path() << std::endl;
    std::stringstream buffer;
    buffer << file.rdbuf();
    file.close();
    return buffer.str();
}

boost::json::value load_json() {
    std::string str_data = load_data();
    if(str_data.empty())
        return boost::json::value();
    boost::json::value value = boost::json::parse(str_data);
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

void added_new_machine(std::string ip_str, std::string port_str) {
    boost::json::value jvalue = load_json();
    boost::json::object jobj;
    if(!jvalue.is_null())
        jobj = jvalue.as_object();
    if(jobj.contains(ip_str))
        jobj.erase(ip_str);
    jobj.emplace(ip_str, port_str);
    save_json(jobj);
}

bool check_machine(std::string ip_str) {
    boost::json::value jvalue = load_json();
    boost::json::object jobj = jvalue.as_object();
    if(jobj.contains(ip_str))
        return true;
    return false;
}

void remove_machine(std::string ip_str) {
    if(!check_machine(ip_str))
        return;
    boost::json::value jvalue = load_json();
    boost::json::object jobj = jvalue.as_object();

    for(auto it = jobj.begin(); it != jobj.end(); it++ ) {
        std::cout << "key=" << it->key() << std::endl;
        if(it->key() == ip_str) {
            jobj.erase(it);
            std::cout << "exist" << std::endl;
            save_json(jobj);
            return;
        }
    }
}
 
void server(unsigned short port)
{
    std::cout << "start sync server" << std::endl;
    enum {max_length = 1024};
    boost::asio::io_service io_service;
    // Создаём сокет и указываем конечной точкой  на каком порту он будет в системе
    for (;;)
    {
        if(my_ip == SIGNAL_SERVER) {
            boost::asio::ip::udp::socket sock(io_service, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 50003));
            // Создаём конечную точку куда будем слать сообщения
            boost::asio::ip::udp::endpoint tmp_ep(boost::asio::ip::address::from_string("178.176.159.182"), 50001);
            std::cout << "send_to " << tmp_ep  << std::endl;
            // Шлё сообщения в целевую конечную точку
            sock.send_to(boost::asio::buffer("#######", 3), tmp_ep);
        } else {
            char data[max_length];
            boost::asio::ip::udp::socket sock(io_service, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 50001));
            boost::asio::ip::udp::endpoint sender_endpoint;
            //std::cout << "start server on: " << sock.local_endpoint() << " mustbe=" << port << std::endl;
            boost::asio::ip::udp::endpoint tmp_ep(boost::asio::ip::address::from_string(SIGNAL_SERVER), 50003);
            //std::cout << "try send_to " << tmp_ep  << std::endl;
            //boost::asio::ip::udp::endpoint server_uep(boost::asio::ip::address::from_string(SIGNAL_SERVER), port);
            //sock.bind( boost::asio::ip::udp::endpoint(boost::asio::ip::address::from_string(SIGNAL_SERVER), port));

            std::cout << "send_to " << tmp_ep  << std::endl;
            sock.send_to(boost::asio::buffer("*******", 3), tmp_ep);


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
        : socket_(io_service, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), port)), t(io_service, boost::posix_time::seconds(1))
    {
    }

private:
public:
    void start_receive()
    {

        socket_.async_receive_from(
                    boost::asio::buffer(buff), remote_endpoint_,
                    boost::bind(&udp_server::handle_receive, this,
                            boost::asio::placeholders::error,
                            boost::asio::placeholders::bytes_transferred));
    }

    void handle_receive(const boost::system::error_code& error, std::size_t bytes_transferred)
    {
        if (!error || error == boost::asio::error::message_size)
        {
            added_new_machine(remote_endpoint_.address().to_string(), std::to_string(remote_endpoint_.port()));
            std::string msg = std::string(buff, bytes_transferred);
            std::cout << msg << std::endl;
            parser(&msg);
            start_receive();
        }
    }

    void handle_send(boost::shared_ptr<std::string> message,
             const boost::system::error_code& /*error*/,
             std::size_t /*bytes_transferred*/)
    {
        std::cout << "sended: " << *message << " | " << remote_endpoint_ << std::endl;
    }

    virtual void parser(std::string *msg){}
    virtual void send_msg(){}

    void send_ping()
    {

        boost::shared_ptr<std::string> msg(new std::string("*****"));
        boost::asio::ip::udp::endpoint server_uep(boost::asio::ip::address::from_string(SIGNAL_SERVER), 50003);
        socket_.async_send_to(boost::asio::buffer(*msg), server_uep,
                      boost::bind(&udp_server::handle_send, this, msg,
                          boost::asio::placeholders::error,
                          boost::asio::placeholders::bytes_transferred));
        t.expires_at(t.expires_at() + boost::posix_time::seconds(1));
        t.async_wait(boost::bind(&udp_server::send_ping, this));
    }
    boost::asio::ip::udp::socket socket_;
    boost::asio::ip::udp::endpoint remote_endpoint_;
    char buff[1024];
    boost::asio::deadline_timer t;
};

class StunServer : public udp_server {
public:
    StunServer(boost::asio::io_service& io_service, int port)
        : udp_server(io_service, port) {

        start_receive();
    }
    virtual void parser(std::string *msg) override {
        std::cout << msg << std::endl;
        boost::shared_ptr<std::string> message(new std::string);
        if(*msg == "list") {
            boost::json::value jvalue = boost::json::parse(load_data());
            boost::json::object jobj;
            jobj.emplace("response", "OK");
            jobj["msg"] = jvalue.as_object();
            message->append(boost::json::serialize(jobj));
        } else {
            message->append("#PING#");
        }
        socket_.async_send_to(boost::asio::buffer(*message), remote_endpoint_,
                      boost::bind(&udp_server::handle_send, this, message,
                          boost::asio::placeholders::error,
                          boost::asio::placeholders::bytes_transferred));
        std::cout << "handle_receive " << remote_endpoint_ << std::endl;
    }
};

class Client : public udp_server {
public:
    Client(boost::asio::io_service& io_service, int port) : udp_server(io_service, port) {
        //t = boost::asio::deadline_timer(io_service, boost::posix_time::seconds(3));
        //boost::system::error_code ec;
        //t.async_wait(boost::bind(&udp_server::send_ping, this));
        remote_endpoint_ = boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::from_string(SIGNAL_SERVER), 50003);
        start_receive();
    }
    virtual void parser(std::string *msg) override {
        std::cout << msg << std::endl;
        boost::json::value jobj = boost::json::parse(*msg).as_object();
        if(jobj.at("response").as_string() == "OK") {
            boost::json::value jmsg = jobj.at("msg").as_object();
            std::cout << jmsg << std::endl;
        } else if(*msg == "connect") {
            std::cout << "connected" << std::endl;
        }
    }

    virtual void send_msg() override {
        boost::shared_ptr<std::string> msg(new std::string);
        std::cin >> *msg;
        socket_.async_send_to(boost::asio::buffer(*msg), server_uep,
                      boost::bind(&Client::handle_send, this, msg,
                          boost::asio::placeholders::error,
                          boost::asio::placeholders::bytes_transferred));

    }

};

int main(int argc, char *argv[]) {

    std::cout << "start programm" << std::endl;
    std::cout << "load: " << load_json() << std::endl;
    my_ip = get_string_myip();
    added_new_machine(my_ip, std::to_string(50001));
    check_machine(my_ip);
    remove_machine(my_ip + "*");
    if(my_ip == SIGNAL_SERVER) {
            boost::asio::io_service io_service;
            StunServer userv(io_service, 50003);
            io_service.run();
    } else if(my_ip == MY_MACHINE) {
        std::cout << "MY MACHINE" << std::endl;
        char buff[1024];
        boost::asio::io_service service;
        Client userv(service, 50001);
        boost::thread(boost::bind(&boost::asio::io_service::run, &service));
        client_session(&userv);
            //std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    } else {
        std::cout << "ANOTHER MACHINE" << std::endl;
        create_packet();
    }    
    return 0;
}

void client_session(Client *client)
{
    try {
        while(true) {
            client->send_msg();
        }
    }
    catch(boost::system::error_code ec) {
        std::cout << "catch exception" << ec.message() << " " << ec.what() << std::endl;
    }
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

