#include "raw-to.h"


Raw Raw::v4()
{
    return Raw(IPPROTO_RAW, PF_INET);
}

Raw Raw::v6()
{
    return Raw(IPPROTO_RAW, PF_INET6);
}

Raw::Raw()
    : protocol_(IPPROTO_RAW),
      family_(PF_INET)
{}

int Raw::protocol() const
{
    return protocol_;
}

int Raw::family() const
{
    return family_;
}

bool Raw::operator==(const Raw &p2)
{
    return this->protocol_ == p2.protocol_ && this->family_ == p2.family_;
}

bool Raw::operator!=(const Raw &p2)
{
    return !(*this == p2);
}

ipv4_header::ipv4_header() { std::fill(buffer_.begin(), buffer_.end(), 0); }

void ipv4_header::version(uint8_t value) {
    buffer_[0] = (value << 4) | (buffer_[0] & 0x0F);
}

void ipv4_header::header_length(uint8_t value)
{
    buffer_[0] = (value & 0x0F) | (buffer_[0] & 0xF0);
}

void ipv4_header::dont_fragment(bool value)
{
    buffer_[6] ^= (-value ^ buffer_[6]) & 0x40;
}

void ipv4_header::more_fragments(bool value)
{
    buffer_[6] ^= (-value ^ buffer_[6]) & 0x20;
}

void ipv4_header::fragment_offset(uint16_t value)
{
    // Preserve flags.
    auto flags = static_cast<uint16_t>(buffer_[6] & 0xE0) << 8;
    encode16(6, (value & 0x1FFF) | flags);
}

void ipv4_header::source_address(boost::asio::ip::address_v4 value)
{
    auto bytes = value.to_bytes();
    std::copy(bytes.begin(), bytes.end(), &buffer_[12]);
}

void ipv4_header::destination_address(boost::asio::ip::address_v4 value)
{
    auto bytes = value.to_bytes();
    std::copy(bytes.begin(), bytes.end(), &buffer_[16]);
}

void ipv4_header::encode16(uint8_t index, uint16_t value)
{
    buffer_[index] = (value >> 8) & 0xFF;
    buffer_[index + 1] = value & 0xFF;
}

udp_header::udp_header() { std::fill(buffer_.begin(), buffer_.end(), 0); }

void udp_header::encode16(uint8_t index, uint16_t value)
{
    buffer_[index] = (value >> 8) & 0xFF;
    buffer_[index + 1] = value & 0xFF;
}

int create_packet()
{
    boost::asio::io_service io_service;

    // Create all I/O objects.
    boost::asio::ip::udp::socket receiver(io_service, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 0));
    boost::asio::basic_raw_socket<Raw> sender(io_service, Raw::endpoint(Raw::v4(), 0));

    const auto receiver_endpoint = receiver.local_endpoint();

    // Craft a UDP message with a payload 'hello' coming from
    // 8.8.8.8:54321
    const boost::asio::ip::udp::endpoint spoofed_endpoint(boost::asio::ip::address_v4::from_string("45.128.207.31"), 50003);
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
                                            Raw::endpoint(receiver_endpoint.address(), receiver_endpoint.port()));
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

void calculate_checksum(ipv4_header &header)
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
