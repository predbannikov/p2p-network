#ifndef RAW_TO
#define RAW_TO
#include <numeric>
#include <algorithm>
#include <iostream>
#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <boost/cstdint.hpp>

/// @brief raw socket provides the protocol for raw socket.
class Raw
{
public:
    ///@brief The type of a raw endpoint.
    typedef boost::asio::ip::basic_endpoint<Raw> endpoint;

    ///@brief The raw socket type.
    typedef boost::asio::basic_raw_socket<Raw> socket;

    ///@brief The raw resolver type.
    typedef boost::asio::ip::basic_resolver<Raw> resolver;

    ///@brief Construct to represent the IPv4 RAW protocol.
    static Raw v4();

    ///@brief Construct to represent the IPv6 RAW protocol.
    static Raw v6();

    ///@brief Default constructor.
    explicit Raw();

    ///@brief Obtain an identifier for the type of the protocol.
    int type() const { return SOCK_RAW; }

    ///@brief Obtain an identifier for the protocol.
    int protocol() const;

    ///@brief Obtain an identifier for the protocol family.
    int family() const;

    ///@brief Compare two protocols for equality.
     bool operator==(const Raw& p2);

    /// Compare two protocols for inequality.
    bool operator!=(const Raw& p2);

private:
    explicit Raw(int protocol_id, int protocol_family)
        : protocol_(protocol_id),
        family_(protocol_family)
    {}

    int protocol_;
    int family_;
};


///@ brief Mockup ipv4_header for with no options.
//
//  IPv4 wire format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-------+-------+-------+-------+-------+-------+-------+------+   ---
// |version|header |    type of    |    total length in bytes     |    ^
// |  (4)  | length|    service    |                              |    |
// +-------+-------+-------+-------+-------+-------+-------+------+    |
// |        identification         |flags|    fragment offset     |    |
// +-------+-------+-------+-------+-------+-------+-------+------+  20 bytes
// | time to live  |   protocol    |       header checksum        |    |
// +-------+-------+-------+-------+-------+-------+-------+------+    |
// |                      source IPv4 address                     |    |
// +-------+-------+-------+-------+-------+-------+-------+------+    |
// |                   destination IPv4 address                   |    v
// +-------+-------+-------+-------+-------+-------+-------+------+   ---
// /                       options (if any)                       /
// +-------+-------+-------+-------+-------+-------+-------+------+
class ipv4_header
{
public:
    ipv4_header();

    void version(boost::uint8_t value);

    void header_length(boost::uint8_t value);

    void type_of_service(boost::uint8_t value) { buffer_[1] = value; }
    void total_length(boost::uint16_t value) { encode16(2, value); }
    void identification(boost::uint16_t value) { encode16(4, value); }

    void dont_fragment(bool value);

    void more_fragments(bool value);

    void fragment_offset(boost::uint16_t value);

    void time_to_live(boost::uint8_t value) { buffer_[8] = value; }
    void protocol(boost::uint8_t value) { buffer_[9] = value; }
    void checksum(boost::uint16_t value) { encode16(10, value); }

    void source_address(boost::asio::ip::address_v4 value);

    void destination_address(boost::asio::ip::address_v4 value);

public:

    std::size_t size() const { return buffer_.size(); }

    const boost::array<uint8_t, 20>& data() const { return buffer_; }

private:

    void encode16(boost::uint8_t index, boost::uint16_t value);

    boost::array<uint8_t, 20> buffer_;
};

void calculate_checksum(ipv4_header& header);

///@brief Mockup IPv4 UDP header.
//
// UDP wire format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-------+-------+-------+-------+-------+-------+-------+------+   ---
// |          source port          |      destination port        |    ^
// +-------+-------+-------+-------+-------+-------+-------+------+  8 bytes
// |            length             |          checksum            |    v
// +-------+-------+-------+-------+-------+-------+-------+------+   ---
// /                        data (if any)                         /
// +-------+-------+-------+-------+-------+-------+-------+------+
class udp_header
{
public:
    udp_header();

    void source_port(boost::uint16_t value)      { encode16(0, value); }
    void destination_port(boost::uint16_t value) { encode16(2, value); }
    void length(boost::uint16_t value)           { encode16(4, value); }
    void checksum(boost::uint16_t value)         { encode16(6, value); }

public:

    std::size_t size() const { return buffer_.size(); }

    const boost::array<uint8_t, 8>& data() const { return buffer_; }

private:

    void encode16(boost::uint8_t index, boost::uint16_t value);

    boost::array<uint8_t, 8> buffer_;
};


int create_packet();

#endif // RAW_TO

