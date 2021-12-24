#include <algorithm>
#include <numeric>
#include <iostream>

#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <boost/cstdint.hpp>

/// @brief raw socket provides the protocol for raw socket.
class raw
{
public:
    ///@brief The type of a raw endpoint.
    typedef boost::asio::ip::basic_endpoint<raw> endpoint;

    ///@brief The raw socket type.
    typedef boost::asio::basic_raw_socket<raw> socket;

    ///@brief The raw resolver type.
    typedef boost::asio::ip::basic_resolver<raw> resolver;

    ///@brief Construct to represent the IPv4 RAW protocol.
    static raw v4()
    {
        return raw(IPPROTO_RAW, PF_INET);
    }

    ///@brief Construct to represent the IPv6 RAW protocol.
    static raw v6()
    {
        return raw(IPPROTO_RAW, PF_INET6);
    }

    ///@brief Default constructor.
    explicit raw()
        : protocol_(IPPROTO_RAW),
        family_(PF_INET)
    {}

    ///@brief Obtain an identifier for the type of the protocol.
    int type() const
    {
        return SOCK_RAW;
    }

    ///@brief Obtain an identifier for the protocol.
    int protocol() const
    {
        return protocol_;
    }

    ///@brief Obtain an identifier for the protocol family.
    int family() const
    {
        return family_;
    }

    ///@brief Compare two protocols for equality.
    friend bool operator==(const raw& p1, const raw& p2)
    {
        return p1.protocol_ == p2.protocol_ && p1.family_ == p2.family_;
    }

    /// Compare two protocols for inequality.
    friend bool operator!=(const raw& p1, const raw& p2)
    {
        return !(p1 == p2);
    }

private:
    explicit raw(int protocol_id, int protocol_family)
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
    ipv4_header() { std::fill(buffer_.begin(), buffer_.end(), 0); }

    void version(boost::uint8_t value) {
        buffer_[0] = (value << 4) | (buffer_[0] & 0x0F);
    }

    void header_length(boost::uint8_t value)
    {
        buffer_[0] = (value & 0x0F) | (buffer_[0] & 0xF0);
    }

    void type_of_service(boost::uint8_t value) { buffer_[1] = value; }
    void total_length(boost::uint16_t value) { encode16(2, value); }
    void identification(boost::uint16_t value) { encode16(4, value); }

    void dont_fragment(bool value)
    {
        buffer_[6] ^= (-value ^ buffer_[6]) & 0x40;
    }

    void more_fragments(bool value)
    {
        buffer_[6] ^= (-value ^ buffer_[6]) & 0x20;
    }

    void fragment_offset(boost::uint16_t value)
    {
        // Preserve flags.
        auto flags = static_cast<uint16_t>(buffer_[6] & 0xE0) << 8;
        encode16(6, (value & 0x1FFF) | flags);
    }

    void time_to_live(boost::uint8_t value) { buffer_[8] = value; }
    void protocol(boost::uint8_t value) { buffer_[9] = value; }
    void checksum(boost::uint16_t value) { encode16(10, value); }

    void source_address(boost::asio::ip::address_v4 value)
    {
        auto bytes = value.to_bytes();
        std::copy(bytes.begin(), bytes.end(), &buffer_[12]);
    }

    void destination_address(boost::asio::ip::address_v4 value)
    {
        auto bytes = value.to_bytes();
        std::copy(bytes.begin(), bytes.end(), &buffer_[16]);
    }

public:

    std::size_t size() const { return buffer_.size(); }

    const boost::array<uint8_t, 20>& data() const { return buffer_; }

private:

    void encode16(boost::uint8_t index, boost::uint16_t value)
    {
        buffer_[index] = (value >> 8) & 0xFF;
        buffer_[index + 1] = value & 0xFF;
    }

    boost::array<uint8_t, 20> buffer_;
};

void calculate_checksum(ipv4_header& header)
{
    // Zero out the checksum.
    header.checksum(0);

    // Checksum is the 16-bit one complement of the one complement sum of
    // all 16-bit words in the header.

    // Sum all 16-bit words.
    auto data = header.data();
    auto sum = std::accumulate<boost::uint16_t*, boost::uint32_t>(
            reinterpret_cast<boost::uint16_t*>(&data[0]),
            reinterpret_cast<boost::uint16_t*>(&data[0] + data.size()),
            0);

    // Fold 32-bit into 16-bits.
    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    header.checksum(~sum);
}

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
    udp_header() { std::fill(buffer_.begin(), buffer_.end(), 0); }

    void source_port(boost::uint16_t value)      { encode16(0, value); }
    void destination_port(boost::uint16_t value) { encode16(2, value); }
    void length(boost::uint16_t value)           { encode16(4, value); }
    void checksum(boost::uint16_t value)         { encode16(6, value); }

public:

    std::size_t size() const { return buffer_.size(); }

    const boost::array<uint8_t, 8>& data() const { return buffer_; }

private:

    void encode16(boost::uint8_t index, boost::uint16_t value)
    {
        buffer_[index] = (value >> 8) & 0xFF;
        buffer_[index + 1] = value & 0xFF;
    }

    boost::array<uint8_t, 8> buffer_;
};


int create_packet()
{
    boost::asio::io_service io_service;

    // Create all I/O objects.
    boost::asio::ip::udp::socket receiver(io_service,
            boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 0));
    boost::asio::basic_raw_socket<raw> sender(io_service,
            raw::endpoint(raw::v4(), 0));

    const auto receiver_endpoint = receiver.local_endpoint();

    // Craft a UDP message with a payload 'hello' coming from
    // 8.8.8.8:54321
    const boost::asio::ip::udp::endpoint spoofed_endpoint(
            boost::asio::ip::address_v4::from_string("8.8.8.8"),
            54321);
    const std::string payload = "hello";

    // Create the UDP header.
    udp_header udp;
    udp.source_port(spoofed_endpoint.port());
    udp.destination_port(receiver_endpoint.port());
    udp.length(udp.size() + payload.size()); // Header + Payload
    udp.checksum(0); // Optioanl for IPv4

    // Create the IPv4 header.
    ipv4_header ip;
    ip.version(4);                   // IPv4
    ip.header_length(ip.size() / 4); // 32-bit words
    ip.type_of_service(0);           // Differentiated service code point
    auto total_length = ip.size() + udp.size() + payload.size();
    ip.total_length(total_length); // Entire message.
    ip.identification(0);
    ip.dont_fragment(true);
    ip.more_fragments(false);
    ip.fragment_offset(0);
    ip.time_to_live(4);
    ip.source_address(spoofed_endpoint.address().to_v4());
    ip.destination_address(receiver_endpoint.address().to_v4());
    ip.protocol(IPPROTO_UDP);
    calculate_checksum(ip);

    // Gather up all the buffers and send through the raw socket.
    boost::array<boost::asio::const_buffer, 3> buffers = {{
        boost::asio::buffer(ip.data()),
            boost::asio::buffer(udp.data()),
            boost::asio::buffer(payload)
    }};
    auto bytes_transferred = sender.send_to(buffers,
            raw::endpoint(receiver_endpoint.address(), receiver_endpoint.port()));
    assert(bytes_transferred == total_length);

    // Read on the reciever.
    std::vector<char> buffer(payload.size(), '\0');
    boost::asio::ip::udp::endpoint sender_endpoint;
    bytes_transferred = receiver.receive_from(
            boost::asio::buffer(buffer), sender_endpoint);

    // Verify.
    assert(bytes_transferred == payload.size());
    assert(std::string(buffer.begin(), buffer.end()) == payload);
    assert(spoofed_endpoint == sender_endpoint);

    // Print endpoints.
    std::cout <<
        "Actual sender endpoint: " << sender.local_endpoint() << "\n"
        "Receiver endpoint: " << receiver.local_endpoint() << "\n"
        "Receiver remote endpoint: " << sender_endpoint << std::endl;
    return 0;
}

