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

#define PATH_JSON   	"map-address"
#define SIGNAL_SERVER   "45.128.207.31"
#define SERVER_PORT 	50003
#define MY_MACHINE		"192.168.0.101"

typedef boost::shared_ptr<boost::asio::ip::tcp::socket> socket_ptr;

class Node;

std::mutex 	mtx_rwfile;
std::string my_ip;

void client_session(Node*);
void client_session_ping(socket_ptr sock, unsigned short port, int timewait);
void remove_machine(std::string ip_str);

std::string get_string_myip() {
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

// The null parser discards all the data
class null_parser
{
    struct handler
    {
        constexpr static std::size_t max_object_size = std::size_t(-1);
        constexpr static std::size_t max_array_size = std::size_t(-1);
        constexpr static std::size_t max_key_size = std::size_t(-1);
        constexpr static std::size_t max_string_size = std::size_t(-1);

        bool on_document_begin( boost::json::error_code& ) { return true; }
        bool on_document_end( boost::json::error_code& ) { return true; }
        bool on_object_begin( boost::json::error_code& ) { return true; }
        bool on_object_end( std::size_t, boost::json::error_code& ) { return true; }
        bool on_array_begin( boost::json::error_code& ) { return true; }
        bool on_array_end( std::size_t, boost::json::error_code& ) { return true; }
        bool on_key_part( boost::json::string_view, std::size_t, boost::json::error_code& ) { return true; }
        bool on_key( boost::json::string_view, std::size_t, boost::json::error_code& ) { return true; }
        bool on_string_part( boost::json::string_view, std::size_t, boost::json::error_code& ) { return true; }
        bool on_string( boost::json::string_view, std::size_t, boost::json::error_code& ) { return true; }
        bool on_number_part( boost::json::string_view, boost::json::error_code& ) { return true; }
        bool on_int64( std::int64_t, boost::json::string_view, boost::json::error_code& ) { return true; }
        bool on_uint64( std::uint64_t, boost::json::string_view, boost::json::error_code& ) { return true; }
        bool on_double( double, boost::json::string_view, boost::json::error_code& ) { return true; }
        bool on_bool( bool, boost::json::error_code& ) { return true; }
        bool on_null( boost::json::error_code& ) { return true; }
        bool on_comment_part(boost::json::string_view, boost::json::error_code&) { return true; }
        bool on_comment(boost::json::string_view, boost::json::error_code&) { return true; }
    };

    boost::json::basic_parser<handler> p_;

public:
    null_parser()
        : p_(boost::json::parse_options())
    {
    }

    ~null_parser()
    {
    }

    std::size_t
    write(
        char const* data,
        std::size_t size,
        boost::json::error_code& ec)
    {
        auto const n = p_.write_some( false, data, size, ec );
        if(! ec && n < size)
            ec = boost::json::error::extra_data;
        return n;
    }
};

bool validate( boost::json::string_view s )
{
    // Parse with the null parser and return false on error
    null_parser p;
    boost::json::error_code ec;
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
    std::lock_guard<std::mutex> lock(mtx_rwfile);
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

class udp_server
{
public:
    udp_server(boost::asio::io_service& io_service, boost::asio::ip::udp::endpoint srv_ep, int port)
        : socket_(io_service, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), port)), addr_srv(srv_ep) , t(io_service, boost::posix_time::seconds(1))
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
        std::cout << "DATA SENDED: " << *message << " from -> " << socket_.local_endpoint() << " to -> " << (listener ? remote_endpoint_ : addr_srv) << std::endl;
    }

    virtual void create_node(boost::asio::ip::udp::endpoint rem_ep) {};

    void parser(std::string *msg) {
        std::cout << "INCOMING DATA: " << *msg << " to -> " << socket_.local_endpoint() << " from -> " << (listener ? remote_endpoint_ : addr_srv) << std::endl;
        added_new_machine(remote_endpoint_.address().to_string(), std::to_string(remote_endpoint_.port()));
        boost::shared_ptr<std::string> message(new std::string);
        auto const valid = validate(*msg);
        boost::json::object jaction;
        //boost::json::object jdata;
        if(valid) {
            boost::json::object jmsg = boost::json::parse(*msg).as_object();
            if(!jmsg.contains("action")) {
                boost::json::object jresponse;
                jresponse.emplace("status", "this pack not contains key action");
                jaction = jresponse;
            } else {
                if(jmsg.at("action").as_string() == "request") {
                    boost::json::object jresponse_msg;
                    jaction.emplace("action", "response");
                    boost::json::object jrequest_parse = jmsg.at("data").as_object();
                    if(jrequest_parse.contains("command")) {

                        jresponse_msg.emplace("status", "ok");
                        boost::json::string str_req = jrequest_parse.at("command").as_string();

                        if(str_req == "list") {
                            boost::json::value jvalue = boost::json::parse(load_data());
                            jresponse_msg.emplace("list", jvalue.as_object());
                        } else if (str_req == "hole punching") {
                            std::cout << "hole punching cmd" << std::endl;
                        } else if (str_req == "myip") {
                            jresponse_msg["myip"] = std::string(remote_endpoint_.address().to_string() + ":" + std::to_string(remote_endpoint_.port()));
                        } else if (str_req == "send") {
                            boost::json::object jparameters = jrequest_parse.at("parameters").as_object();
                            std::cout << jparameters.at("message").as_string() << std::endl;
                        } else if (str_req == "relay") {
                            boost::json::object jparameters = jrequest_parse.at("parameters").as_object();
                            boost::asio::ip::udp::endpoint ep(boost::asio::ip::address_v4::from_string(boost::json::value_to<std::string>(jparameters.at("IP"))),
                                              std::stoi(boost::json::value_to<std::string>(jparameters.at("PORT"))));
                            boost::json::object jrelay;
                            jrelay.emplace("action", "connect");
                            boost::json::object jconnect;
                            jconnect.emplace("IP", remote_endpoint_.address().to_string());
                            jconnect.emplace("PORT", std::to_string(remote_endpoint_.port()));
                            jconnect.emplace("payload", jparameters.at("payload"));
                            jrelay.emplace("data", jconnect);
                            boost::shared_ptr<std::string> relay_ptr(new std::string);
                            *relay_ptr = boost::json::serialize(jrelay);
                            socket_.async_send_to(boost::asio::buffer(*relay_ptr), ep,
                                      boost::bind(&udp_server::handle_send, this, relay_ptr,
                                              boost::asio::placeholders::error,
                                              boost::asio::placeholders::bytes_transferred));
                        }
                    } else {
                        std::cout << "package not contain key command" << std::endl;
                        jresponse_msg.emplace("status", "error");
                    }
                    jaction.emplace("data",jresponse_msg);
                    send_pack(jaction);
                } else if(jmsg.at("action").as_string() == "connect") {
                    //jpayload.emplace("status", "ok");
                    jaction.emplace("action", "request");
                    boost::json::object jdata = jmsg.at("data").as_object();
                    boost::json::object jpayload = jdata.at("payload").as_object();
                    boost::json::object jpayload_msg;
                    if(jpayload.at("STATE").as_string() == "SYN") {
                        boost::json::object jrequest;
                        boost::json::object jparameters;
                        switch (state_connect) {
                        case STATE_CONNECT_STUN:
                            jpayload_msg.emplace("STATE", "ACK");
                            jrequest.emplace("command", "relay");
                            jparameters.emplace("IP", jdata.at("IP"));
                            jparameters.emplace("PORT", jdata.at("PORT"));
                            jparameters.emplace("payload", jpayload_msg);
                            jrequest.emplace("parameters", jparameters);
                            jaction.emplace("data", jrequest);
                            state_connect = STATE_CONNECT_CLIENT_STUN_MIDDLE;
                            break;
                        case STATE_CONNECT_CLIENT_STUN_MIDDLE:
                            jpayload_msg.emplace("STATE", "ACK");
                            jrequest.emplace("command", "relay");
                            jparameters.emplace("IP", jdata.at("IP"));
                            jparameters.emplace("PORT", jdata.at("PORT"));

                            std::cout << "OTHER CLIENT OPENING PORT: " << jpayload.at("PORT").as_string() << std::endl;


                            {
                                boost::asio::ip::udp::endpoint rem_ep(boost::asio::ip::address_v4::from_string(boost::json::value_to<std::string>(jdata.at("IP"))),
                                                                      std::stoi(boost::json::value_to<std::string>(jpayload.at("PORT"))));
                                create_node(rem_ep);
                                state_connect = STATE_CONNECT_STUN;
                            }

                            jparameters.emplace("payload", jpayload_msg);
                            jrequest.emplace("parameters", jparameters);
                            jaction.emplace("data", jrequest);
                            state_connect = STATE_CONNECT_CLIENT_STUN_MIDDLE;

                            break;
                        default:
                            std::cout << "default STATE_CONNECTION" << std::endl;
                        }
                        send_pack(jaction);
                    } else if(jpayload.at("STATE").as_string() == "ACK") {
                        jpayload_msg.emplace("OPENING_PORT", 50005);
                        boost::asio::io_service srvc;
                        std::cout << "client connect success:" << std::endl;
                        state_connect = STATE_CONNECT_CLIENT;
                    }


                } else if(jmsg.at("action").as_string() == "response") {
                    boost::json::object jresponse = jmsg.at("data").as_object();
                    if(jresponse.contains("status")) {
                        if(jresponse.at("status").as_string() == "ok") {
                            std::cout << "ok." << std::endl;
                            state_connection = true;
                        }
                    }
                    if(jresponse.contains("list")) {
                        boost::json::object jlist = jresponse.at("list").as_object();
                        save_json(jlist);
                        int counter = 0;
                        std::cout << "list machines: " << std::endl;
                        for(auto &item: jlist) {
                            std::cout << counter << ". " << item.key() << ":" << std::atoi(item.value().as_string().c_str()) << std::endl;
                            counter++;
                        }
                    }
                    if(jresponse.contains("myip")) {
                            std::cout << "Ext ip: " << jresponse.at("myip").as_string() << std::endl;
                    }
                    if(jresponse.contains("connect")) {
                        std::cout << "connection request with " << jresponse.at("connect").as_string() << std::endl;
                    }
                } else {
                    std::cout << "don't known type action" << std::endl;
                }
            }

        } else {
            std::cout << "RAW response: " << *msg << "\nok. punching stop \n" << std::endl;
            send_pack(jaction );
        }
        std::cout << std::endl << socket_.local_endpoint() << "\n>" << std::flush;

        //        socket_.async_send_to(boost::asio::buffer(*message), remote_endpoint_,
        //                  boost::bind(&udp_server::handle_send, this, message,
        //                          boost::asio::placeholders::error,
        //                          boost::asio::placeholders::bytes_transferred));
    }

    void send_pack(boost::json::object &jobj) {
        boost::shared_ptr<std::string> serialise_data(new std::string);
        serialise_data->append(boost::json::serialize(jobj));
        sock_send(serialise_data);
    }

    virtual void sock_send(boost::shared_ptr<std::string> message) {}
    virtual void connect(std::string str_ip, std::string str_port) {}

    void send_ping(std::string str_ip, std::string str_port)
    {
        boost::shared_ptr<std::string> msg(new std::string("{\"action\":\"request\",\"data\":{\"command\":\"hole punching\"}}"));
//        boost::asio::ip::udp::endpoint server_uep(boost::asio::ip::address::from_string(SIGNAL_SERVER), 50003);
        socket_.async_send_to(boost::asio::buffer(*msg), addr_srv,
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
    bool state_connection = false;
    boost::asio::ip::udp::endpoint addr_srv;

    enum STATE_CONN_P2P {
        STATE_SYN, STATE_ACK
    } state_conn_p2p;

    enum STATE_CONNECT {
        STATE_CONNECT_STUN, STATE_CONNECT_CLIENT, STATE_CONNECT_CLIENT_STUN_MIDDLE
    } state_connect = STATE_CONNECT_STUN;

    bool listener;
};

class StunServer : public udp_server {
public:
    StunServer(boost::asio::io_service& io_service, int port)
        : udp_server(io_service, boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::from_string(SIGNAL_SERVER), 50003), port) {
        start_receive();
    }
    virtual void  sock_send(boost::shared_ptr<std::string> message) override {
        socket_.async_send_to(boost::asio::buffer(*message), remote_endpoint_,
                  boost::bind(&udp_server::handle_send, this, message,
                          boost::asio::placeholders::error,
                          boost::asio::placeholders::bytes_transferred));


    }
};

class Node : public udp_server {
public:
    Node(boost::asio::io_service& io_service, boost::asio::ip::udp::endpoint srv_ep, int port, bool listen = true) : udp_server(io_service, srv_ep, port) {
        std::cout << "start client for connection to -" << srv_ep << std::endl;
        //t = boost::asio::deadline_timer(io_service, boost::posix_time::seconds(3));
        //boost::system::error_code ec;
        //t.async_wait(boost::bind(&udp_server::send_ping, this));
        remote_endpoint_ = srv_ep;
        //remote_endpoint_ = boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::from_string(str_remove_address), 50003);
        //start_receive();
        listener = listen;
        if(listener)
            start_receive();
        else
            connect(srv_ep.address().to_string(), std::to_string(srv_ep.port()));
    }

    void send_msg() {
        std::vector<std::string> args;
        std::string msg;
        std::string cmd;
        std::getline(std::cin, msg);
        std::istringstream is(msg);
        int argc = 0;
        while (is) {
            std::string word;
            is >> word;
            if(argc != 0 && !word.empty())
                args.push_back(word);
            if(argc == 0)
                cmd = word;
            argc++;
        }
        boost::json::array jdata;
        for(size_t i = 0; i < args.size(); i++)
            jdata.emplace_back(args[i]);
        send_request(cmd, jdata);
    }

    virtual void create_node(boost::asio::ip::udp::endpoint rem_ep) override {
        boost::asio::io_service *iosrv = new boost::asio::io_service();
        Node *new_node = new Node(*iosrv, rem_ep, 50055, false);
        boost::thread(boost::bind(&boost::asio::io_service::run, iosrv));
        boost::thread(boost::bind(&Node::start_receive, new_node));
        nodes.push_back(new_node);
    }

    virtual void  sock_send(boost::shared_ptr<std::string> message) override {
        if(!listener)
            socket_.async_send_to(boost::asio::buffer(*message), addr_srv,
                  boost::bind(&udp_server::handle_send, this, message,
                          boost::asio::placeholders::error,
                          boost::asio::placeholders::bytes_transferred));
        else
            socket_.async_send_to(boost::asio::buffer(*message), remote_endpoint_,
                  boost::bind(&udp_server::handle_send, this, message,
                          boost::asio::placeholders::error,
                          boost::asio::placeholders::bytes_transferred));
    }

    void send_request(std::string &cmd, boost::json::array &jdata_array) {
        boost::json::object jaction;
        jaction.emplace("action", "request");
        boost::json::object jrequest_msg;
        boost::json::object jparameters;
        boost::json::object jpayload;
        switch (state_connect) {
        case STATE_CONNECT_STUN:
            if(cmd == "list")
                jrequest_msg["command"] = cmd;
            else if(cmd == "myip")
                jrequest_msg["command"] = cmd;
            else if(cmd == "send") {
                jrequest_msg["command"] = cmd;
                std::cout << "jdata_array " << jdata_array << std::endl;
                std::string message;
                for(auto &item: jdata_array) {
                    message.append(boost::json::value_to<std::string>(item));
                    message.append(" ");
                }
                jparameters.emplace("message", message);
                jrequest_msg.emplace("parameters", jparameters);
            }
            else if(cmd == "connect") {
                if(!jdata_array.empty() && is_number(boost::json::value_to<std::string>(jdata_array.at(0)))){
                    jrequest_msg["command"] = "relay";

                    std::string ss = boost::json::value_to<std::string>(jdata_array.at(0));
                    int numberPC = std::stoi(ss);
                    boost::json::object jlistPC = load_json().as_object();
                    int i = 0;
                    for(auto &item: jlistPC) {
                        if(i == numberPC) {
                            jparameters.emplace("IP", item.key());
                            jparameters.emplace("PORT", item.value());
                            jpayload.emplace("STATE", "SYN");
                            jparameters.emplace("payload", jpayload);
                        }
                        i++;
                    }
                    jrequest_msg.emplace("parameters", jparameters);
                    jsave_request = jrequest_msg;
                } else {
                    std::cout << "PC number is required from list of connections" << std::endl;
                }
            } else if(cmd == "exit") {
                socket_.close();
                exit(0);
            }
            break;
        case STATE_CONNECT_CLIENT:
            if(cmd == "PORT") {
                if(!jdata_array.empty() && is_number(boost::json::value_to<std::string>(jdata_array.at(0)))){
                    jrequest_msg = jsave_request;
                    jparameters = jrequest_msg.at("parameters").as_object();
                    jrequest_msg.erase("parameters");
                    jpayload = jparameters.at("payload").as_object();
                    jparameters.erase("payload");
                    jpayload.emplace("PORT", "50055");
                    boost::asio::ip::udp::endpoint rem_ep(boost::asio::ip::address_v4::from_string(boost::json::value_to<std::string>(jparameters.at("IP"))), 50055);
                    //boost::asio::ip::udp::endpoint rem_ep(boost::asio::ip::address_v4::from_string(SIGNAL_SERVER), 50003);
                    create_node(rem_ep);
                    jparameters.emplace("payload", jpayload);
                    jrequest_msg.emplace("parameters", jparameters);

                } else {
                    std::cout << "second parameter not recognized" << std::endl;
                }
            } else if(cmd == "exit") {
                state_connect = STATE_CONNECT_STUN;
            }
            std::cout << "client state" << std::endl;
            break;
        default:
            std::cout << "STATE_CONNECT default case" << std::endl;
        }
        if(cmd == "node") {
            if(!jdata_array.empty()) {
                std::cout << "RAW jdata_array: " << jdata_array << std::endl;
                std::string cmd_node = boost::json::value_to<std::string>(jdata_array.at(0));
                boost::json::array jdata_array_new;
                for(int i = 1; i < jdata_array.size(); i++)
                    jdata_array_new.emplace_back(jdata_array.at(i));

                std::cout << "CMD: " << cmd_node << " ARGS: " << jdata_array_new << std::endl;
                nodes.front()->send_request(cmd_node, jdata_array_new);
                return;
            }
        }

        jaction.emplace("data", jrequest_msg);
        send_pack(jaction);
    }


    virtual void connect(std::string str_ip, std::string str_port) override {
        if(!state_connection)
            send_ping(str_ip, str_port);
    }

    void proc_init_p2p() {
        std::string cmd;
        std::string data;
        switch (state_conn_p2p) {
        case STATE_SYN:
            cmd = "machine 1";
            data = "SYN";
            //send_pack(cmd, data);
            break;
        case STATE_ACK:
            break;
        default:
            return;
        }

        t.expires_at(t.expires_at() + boost::posix_time::seconds(1));
        t.async_wait(boost::bind(&Node::proc_init_p2p, this));
    }

    bool is_number(const std::string& s)
    {
        std::string::const_iterator it = s.begin();
        while (it != s.end() && std::isdigit(*it)) ++it;
        return !s.empty() && it == s.end();
    }
    boost::json::object jsave_request;
    std::vector<Node *> nodes;
};

int main(int argc, char *argv[]) {

    std::cout << "\n*** start programm ***" << std::endl;
    std::cout << "load: " << load_json() << std::endl;
    my_ip = get_string_myip();
    try {
        if(my_ip == SIGNAL_SERVER) {
            boost::asio::io_service io_service;
            //StunServer userv(io_service, 50003);
            Node node(io_service, boost::asio::ip::udp::endpoint(), 50003, true);
            io_service.run();
        } else {
            std::cout << "CLIENT MACHINE" << std::endl;
            char buff[1024];
            boost::asio::io_service service;
            Node node(service, boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::from_string(SIGNAL_SERVER), 50003), 50001, false);
            boost::thread(boost::bind(&boost::asio::io_service::run, &service));
            client_session(&node);

        }
    }  catch (boost::system::error_code ec) {
        std::cout << ec.message() << std::endl << ec.what() << std::endl;
    }
    return 0;
}

void client_session(Node *client)
{
    try {
        client->start_receive();
        while(true) {
            client->send_msg();
        }
    }
    catch(boost::system::error_code ec) {
        std::cout << "catch exception" << ec.message() << " " << ec.what() << std::endl;
    }
    catch(...) {
        std::cout << "unknown error" << std::endl;
    }
}
