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
#include <boost/json/basic_parser_impl.hpp>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <thread>
#include "raw-to.h"

using namespace boost::asio::ip;

#define PATH_JSON   	"map-address"
#define SIGNAL_SERVER   "45.128.207.31"
#define SERVER_PORT 	50003
#define MY_MACHINE		"192.168.0.101"

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


//#include "file.hpp"

using namespace boost::json;

// The null parser discards all the data
class null_parser
{
    struct handler
    {
        constexpr static std::size_t max_object_size = std::size_t(-1);
        constexpr static std::size_t max_array_size = std::size_t(-1);
        constexpr static std::size_t max_key_size = std::size_t(-1);
        constexpr static std::size_t max_string_size = std::size_t(-1);

        bool on_document_begin( error_code& ) { return true; }
        bool on_document_end( error_code& ) { return true; }
        bool on_object_begin( error_code& ) { return true; }
        bool on_object_end( std::size_t, error_code& ) { return true; }
        bool on_array_begin( error_code& ) { return true; }
        bool on_array_end( std::size_t, error_code& ) { return true; }
        bool on_key_part( string_view, std::size_t, error_code& ) { return true; }
        bool on_key( string_view, std::size_t, error_code& ) { return true; }
        bool on_string_part( string_view, std::size_t, error_code& ) { return true; }
        bool on_string( string_view, std::size_t, error_code& ) { return true; }
        bool on_number_part( string_view, error_code& ) { return true; }
        bool on_int64( std::int64_t, string_view, error_code& ) { return true; }
        bool on_uint64( std::uint64_t, string_view, error_code& ) { return true; }
        bool on_double( double, string_view, error_code& ) { return true; }
        bool on_bool( bool, error_code& ) { return true; }
        bool on_null( error_code& ) { return true; }
        bool on_comment_part(string_view, error_code&) { return true; }
        bool on_comment(string_view, error_code&) { return true; }
    };

    basic_parser<handler> p_;

public:
    null_parser()
        : p_(parse_options())
    {
    }

    ~null_parser()
    {
    }

    std::size_t
    write(
        char const* data,
        std::size_t size,
        error_code& ec)
    {
        auto const n = p_.write_some( false, data, size, ec );
        if(! ec && n < size)
            ec = error::extra_data;
        return n;
    }
};

bool validate( string_view s )
{
    // Parse with the null parser and return false on error
    null_parser p;
    error_code ec;
    p.write( s.data(), s.size(), ec );
    if( ec )
        return false;

    // The string is valid JSON.
    return true;
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
    const auto valid = validate(str_data);
    if(!valid) {
        std::cout << "json data of " << boost::filesystem::absolute(PATH_JSON)  << " is not valid" << std::endl;
        exit(-1);
    }
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
            std::string msg = std::string(buff, bytes_transferred);
            parser(&msg);
            start_receive();
        }
    }

    void handle_send(boost::shared_ptr<std::string> message,
             const boost::system::error_code& /*error*/,
             std::size_t /*bytes_transferred*/)
    {
        std::cout << "data sended: " << *message << " to -> " << remote_endpoint_ << std::endl;
    }

    virtual void parser(std::string *msg) {}
    virtual void send_msg() {}
    virtual void connect(std::string str_ip, std::string str_port) {}

    void send_ping(std::string str_ip, std::string str_port)
    {
        boost::shared_ptr<std::string> msg(new std::string("hole punching"));
//        boost::asio::ip::udp::endpoint server_uep(boost::asio::ip::address::from_string(SIGNAL_SERVER), 50003);
        socket_.async_send_to(boost::asio::buffer(*msg), remote_endpoint_,
                      boost::bind(&udp_server::handle_send, this, msg,
                          boost::asio::placeholders::error,
                          boost::asio::placeholders::bytes_transferred));
        t.expires_at(t.expires_at() + boost::posix_time::seconds(1));
        t.async_wait(boost::bind(&udp_server::connect, this, str_ip, str_port));
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
        added_new_machine(remote_endpoint_.address().to_string(), std::to_string(remote_endpoint_.port()));
        boost::shared_ptr<std::string> message(new std::string);
        auto const valid = validate(*msg);
        if(valid) {
            boost::json::value jobj = boost::json::parse(*msg).as_object();

        } else {
            if(*msg == "list") {
                boost::json::value jvalue = boost::json::parse(load_data());
                boost::json::object jobj;
                jobj.emplace("response", "OK");
                jobj["msg"] = jvalue.as_object();
                message->append(boost::json::serialize(jobj));
            } else if(*msg == "hole punching") {
                message->append("Hole punched?");
            } else {
                message->append("#PING#");
            }
        }
        socket_.async_send_to(boost::asio::buffer(*message), remote_endpoint_,
                      boost::bind(&StunServer::handle_send, this, message,
                          boost::asio::placeholders::error,
                          boost::asio::placeholders::bytes_transferred));
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
        connect(SIGNAL_SERVER, std::to_string(SERVER_PORT));
    }
    virtual void parser(std::string *msg) override {
        auto const valid = validate(*msg);
        if(valid) {
            boost::json::value jobj = boost::json::parse(*msg).as_object();
            if(jobj.at("response").as_string() == "OK") {
                boost::json::object jmsg = jobj.at("msg").as_object();
                std::cout << "\nOK." << std::endl;
                int counter = 0;
                std::cout << "List machines: " << std::endl;
                for(auto &item: jmsg) {
                    if(item.key() == my_ip)
                        continue;
                    std::cout << counter << ". " << item.key() << ":" << std::atoi(item.value().as_string().c_str()) << std::endl;
                    counter++;
                }
            } else  {
                std::cout << "not correct request" << std::endl;
            }
        } else {
            if(*msg == "Hole punched?") {
                state_connection = true;
                std::cout << "RESPONSE: " << *msg << "\nOk. punching stop \n" << std::endl;
            } else {
                std::cout << "Response data not valid " << *msg << std::endl;
            }
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

    virtual void connect(std::string str_ip, std::string str_port) override {
        if(!state_connection)
            send_ping(str_ip, str_port);
    }
    bool state_connection = false;
};

int main(int argc, char *argv[]) {

    std::cout << "*** start programm ***" << std::endl;
    std::cout << "load: " << load_json() << std::endl;
    my_ip = get_string_myip();
    if(my_ip == SIGNAL_SERVER) {
            boost::asio::io_service io_service;
            StunServer userv(io_service, 50003);
            io_service.run();
    } else {
        std::cout << "CLIENT MACHINE" << std::endl;
        char buff[1024];
        boost::asio::io_service service;
        Client userv(service, 50001);
        boost::thread(boost::bind(&boost::asio::io_service::run, &service));
        client_session(&userv);
    //std::this_thread::sleep_for(std::chrono::milliseconds(1000));
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

