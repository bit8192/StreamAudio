#include "device.h"
#include "logger.h"
#include "tools/base64.h"
#include <stdexcept>
#include <cstring>

#include "config.h"
#include "platform/audio_server.h"
#include "tools/hextool.h"

#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")
#endif

constexpr const char* TAG = "Device";

// Helper function to derive UDP audio key from TCP session key
static std::vector<uint8_t> derive_udp_audio_key(const std::vector<uint8_t>& tcp_session_key) {
    std::vector<uint8_t> salt = {'u','d','p','-','a','u','d','i','o'};
    std::vector<uint8_t> info = {'s','t','r','e','a','m','-','a','u','d','i','o','-','v','1'};
    std::vector<uint8_t> combined = salt;
    combined.insert(combined.end(), info.begin(), info.end());
    return Crypto::hmac_sha256(tcp_session_key, combined);
}

Device::Device(std::shared_ptr<AudioServer> server, DeviceConfig config, const long msg_wait_timeout)
    : server_(std::move(server)),
      config(std::move(config)),
      msg_wait_timeout(msg_wait_timeout),
      socket_fd(INVALID_SOCKET),
      connected(false),
      ecdh_completed(false),
      message_id_counter(0),
      queue_num_counter(0),
      udp_socket(INVALID_SOCKET),
      udp_streaming(false),
      udp_sequence_num(0),
      audio_data_available(false)
{
    // 加载公钥（如果配置中有）
    if (!this->config.public_key.empty())
    {
        try
        {
            auto key_data = Base64::decode(this->config.public_key);
            public_key = std::make_shared<Crypto::ED25519>(
                Crypto::ED25519::load_public_key_from_mem(Base64::decode(config.public_key)));
        }
        catch (const std::exception& e)
        {
            Logger::w(TAG, "Failed to load public key: " + std::string(e.what()));
        }
    }

    session_key.resize(32, 0);
}

Device::Device(std::shared_ptr<AudioServer> server, const socket_t socket_fd, const long msg_wait_timeout)
    : server_(std::move(server)),
      config(DeviceConfig("", "", "")),
      msg_wait_timeout(msg_wait_timeout),
      socket_fd(socket_fd),
      connected(true),
      ecdh_completed(false),
      message_id_counter(0),
      queue_num_counter(0),
      udp_socket(INVALID_SOCKET),
      udp_streaming(false),
      udp_sequence_num(0),
      audio_data_available(false)
{
    session_key.resize(32, 0);
}

Device::~Device()
{
    // Stop UDP streaming if active
    if (udp_streaming) {
        udp_streaming = false;
        if (udp_send_thread.joinable()) {
            // Wake up the UDP thread
            {
                std::lock_guard<std::mutex> lock(audio_buffer_mutex);
                audio_data_available = true;
            }
            audio_buffer_cv.notify_all();
            udp_send_thread.join();
        }
        close_udp_socket();
    }

    disconnect();
}

bool Device::parse_address(const std::string& address, std::string& host, int& port)
{
    if (address.empty()) return false;
    auto colon_pos = address.find(':');
    if (colon_pos == std::string::npos)
    {
        host = address;
        port = STREAMAUDIO_CONFIG_DEFAULT_PORT; // 默认端口
    }
    else
    {
        host = address.substr(0, colon_pos);
        try
        {
            port = std::stoi(address.substr(colon_pos + 1));
        }
        catch (...)
        {
            Logger::w(TAG, "invalid device port: " + address);
            port = STREAMAUDIO_CONFIG_DEFAULT_PORT;
        }
    }
    return true;
}

void Device::connect()
{
    if (connected)
    {
        Logger::w(TAG, "Device [" + config.name + "] already connected, disconnecting first");
        disconnect();
    }

    std::string host;
    int port;
    parse_address(config.address, host, port);

    Logger::i(TAG, "Connecting to " + host + ":" + std::to_string(port));

    // 创建 socket
    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == INVALID_SOCKET)
    {
        throw std::runtime_error("Failed to create socket");
    }

    // 设置地址
    struct sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(static_cast<uint16_t>(port));

#ifdef _WIN32
    server_addr.sin_addr.s_addr = inet_addr(host.c_str());
#else
    if (inet_pton(AF_INET, host.c_str(), &server_addr.sin_addr) <= 0)
    {
        close_socket();
        throw std::runtime_error("Invalid address: " + host);
    }
#endif

    // 连接
    if (::connect(socket_fd, reinterpret_cast<struct sockaddr*>(&server_addr), sizeof(server_addr)) < 0)
    {
        close_socket();
        throw std::runtime_error("Failed to connect to " + host + ":" + std::to_string(port));
    }

    Logger::i(TAG, "Device [" + config.name + "] connected successfully");

    start_listening();
}

void Device::close_connection()
{
    // 只停止连接，不等待线程（用于从 listening_loop 内部调用）
    if (connected)
    {
        connected = false;
        close_socket();

        // 通知 AudioServer 检查并清理设备
        server_->notify_device_disconnected();
    }
}

void Device::disconnect()
{
    if (connected)
    {
        close_connection();
    }

    // 等待监听线程结束（只有在外部调用时才 join）
    if (listen_thread.joinable())
    {
        listen_thread.join();
    }

    Logger::d(TAG, "Device [" + config.name + "] disconnected");
}

void Device::close_socket()
{
    if (socket_fd != INVALID_SOCKET)
    {
#ifdef _WIN32
        closesocket(socket_fd);
#else
        ::close(socket_fd);
#endif
        socket_fd = INVALID_SOCKET;
    }
}

bool Device::is_connected() const
{
    return connected && socket_fd != INVALID_SOCKET;
}

void Device::start_listening()
{
    connected = true;
    // 启动监听线程
    listen_thread = std::thread(&Device::listening_loop, this);
}

void Device::check_connection() const
{
    if (!is_connected())
    {
        throw std::runtime_error("Device [" + config.name + "] not connected");
    }
}

ssize_t Device::socket_send(const uint8_t* data, size_t len) const
{
#ifdef _WIN32
    return ::send(socket_fd, reinterpret_cast<const char*>(data), static_cast<int>(len), 0);
#else
    return ::send(socket_fd, data, len, 0);
#endif
}

ssize_t Device::socket_recv(uint8_t* buffer, size_t len) const
{
#ifdef _WIN32
    return ::recv(socket_fd, reinterpret_cast<char*>(buffer), static_cast<int>(len), 0);
#else
    return ::recv(socket_fd, buffer, len, 0);
#endif
}

void Device::listening_loop()
{
    std::vector<uint8_t> buffer;
    buffer.resize(2048);

    try
    {
        size_t offset = 0;
        while (connected)
        {
            const ssize_t bytes_read = socket_recv(buffer.data() + offset, buffer.size() - offset);

            if (bytes_read <= 0)
            {
                // 连接断开或出错
                if (bytes_read < 0)
                {
                    Logger::e(TAG, "Socket read error for device [" + config.name + "]");
                }
                else
                {
                    Logger::i(TAG, "Connection closed for device [" + config.name + "]");
                }
                break;
            }

            // 解析消息
            size_t read_offset = 0;
            while (read_offset < offset + bytes_read)
            {
                size_t bytes_consumed = 0;

                if (auto msg_opt = Message::parse(buffer.data() + offset, bytes_read + offset - read_offset,
                                                  bytes_consumed, public_key))
                {
                    handle_received_message(*msg_opt);
                    offset += bytes_consumed;
                }
                else
                {
                    Logger::d(TAG, "invalid message: {}",
                              HEX_TOOL::to_hex(buffer.data() + offset, bytes_read + offset - read_offset));
                    break;
                }
            }

            if (read_offset < offset + bytes_read)
            {
                size_t&& remaining = offset + bytes_read - read_offset;
                memcpy(buffer.data(), buffer.data() + read_offset, read_offset);
                offset = remaining;
            }
            else
            {
                offset = 0;
            }
        }
    }
    catch (const std::exception& e)
    {
        Logger::e(TAG, "Exception in listening loop: " + std::string(e.what()));
        std::lock_guard<std::mutex> lock(callback_mutex);
        if (error_callback)
        {
            error_callback(e.what());
        }
    }

    // 监听结束，关闭连接（不 join 自己）
    close_connection();

    Logger::d(TAG, "Device [" + config.name + "] listening loop ended");
}

void Device::handle_received_message(const Message& msg)
{
    Logger::d(TAG, "Received message: magic=" + std::string(to_string(msg.magic)) +
              " id=" + std::to_string(msg.id));

    switch (msg.magic)
    {
    case ProtocolMagic::ENCRYPTED:
        {
            if (!is_ecdh_completed())
            {
                Logger::w(TAG, "Received ENCRYPTED message before ECDH completion, ignoring");
                return;
            }
            const auto msg_body = std::dynamic_pointer_cast<ByteArrayMessageBody>(msg.body);
            if (!msg_body)
            {
                Logger::w(TAG, "Invalid ENCRYPTED message body");
                return;
            }
            const auto decrypted_msg_opt = msg_body->decrypt_aes256gcm(
                session_key,
                public_key
            );
            if (decrypted_msg_opt)
            {
                return handle_received_message(*decrypted_msg_opt);
            }
        }
    case ProtocolMagic::PAIR:
        {
            if (server_->get_pair_code().empty())
            {
                Logger::w(TAG, "Received PAIR message but server has no active pair code, ignoring");
                return;
            }
            auto msg_body = std::dynamic_pointer_cast<ByteArrayMessageBody>(msg.body);
            if (!msg_body)
            {
                Logger::w(TAG, "Invalid PAIR message body");
                return;
            }
            auto key = Crypto::sha256(std::vector<uint8_t>(
                    server_->get_pair_code().begin(),
                    server_->get_pair_code().end())
            );
            const auto decrypted_msg = msg_body->decrypt_aes256gcm(key, public_key);
            if (!decrypted_msg.has_value())
            {
                Logger::w(TAG, "Failed to decrypt PAIR message");
                return;
            }
            msg_body = std::dynamic_pointer_cast<ByteArrayMessageBody>(decrypted_msg.value().body);
            if (!msg_body)
            {
                Logger::w(TAG, "Invalid decrypted PAIR message body");
                return;
            }
            public_key = std::make_shared<Crypto::ED25519>(Crypto::ED25519::load_public_key_from_mem(msg_body->data));
            Logger::d(TAG, "Device [{}] paired key, publicKey={}",
                      config.name,
                      HEX_TOOL::to_hex(public_key->export_public_key().data(), public_key->export_public_key().size())
            );
            key = Crypto::sha256(public_key->export_public_key());
            send_message(Message::build(
                ProtocolMagic::PAIR_RESPONSE,
                queue_num_counter.fetch_add(1),
                msg.id,
                std::make_shared<ByteArrayMessageBody>(ByteArrayMessageBody::build_aes256gcm_encrypted_body(server_->get_sign_key()->export_public_key(), key))
            ));
        }
    case ProtocolMagic::ECDH:
        {
            // Check if client public key exists
            if (!public_key) {
                Logger::w(TAG, "Received ECDH without client public key");
                return;
            }

            auto msg_body = std::dynamic_pointer_cast<ByteArrayMessageBody>(msg.body);
            if (!msg_body) {
                Logger::w(TAG, "Invalid ECDH message body");
                return;
            }

            // Decrypt client X25519 public key using clientEd25519PublicKey.sha256()
            auto decrypt_key = Crypto::sha256(public_key->export_public_key());
            auto decrypted_msg_opt = msg_body->decrypt_aes256gcm(decrypt_key, nullptr);

            if (!decrypted_msg_opt) {
                Logger::w(TAG, "Failed to decrypt ECDH message");
                return;
            }

            auto decrypted_body = std::dynamic_pointer_cast<ByteArrayMessageBody>(
                decrypted_msg_opt->body);

            if (!decrypted_body || decrypted_body->data.size() != 32) {
                Logger::w(TAG, "Invalid decrypted ECDH body");
                return;
            }

            // 处理客户端的 ECDH 请求
            // 使用客户端公钥派生会话密钥
            auto derived_key = server_->ecdh_key(decrypted_body->data);

            // 保存会话密钥
            if (derived_key.size() >= 32)
            {
                std::copy(derived_key.begin(), derived_key.begin() + 32, session_key.begin());
                ecdh_completed = true;
                Logger::d(TAG, "Device [{}] ECDH completed (server side) sessionKey={}", config.name,
                          HEX_TOOL::to_hex(session_key.data(), session_key.size()));
            }
            else
            {
                Logger::e(TAG, "Derived shared secret too short");
                return;
            }

            // Encrypt server X25519 public key with clientEd25519PublicKey.sha256()
            auto server_pub_key = server_->get_ecdh_pub_key_data();
            auto encrypt_key = Crypto::sha256(public_key->export_public_key());

            auto encrypted_body = ByteArrayMessageBody::build_aes256gcm_encrypted_body(
                server_pub_key, encrypt_key);

            // 返回服务器的公钥
            send_message(Message::build(ProtocolMagic::ECDH_RESPONSE, queue_num_counter.fetch_add(1), msg.id,
                                        std::make_shared<ByteArrayMessageBody>(encrypted_body)));
            break;
        }
    case ProtocolMagic::PLAY:
        {
            // Check if ECDH is completed
            if (!is_ecdh_completed()) {
                Logger::w(TAG, "Received PLAY before ECDH completion");
                send_message(Message::build(
                    ProtocolMagic::ERROR,
                    queue_num_counter.fetch_add(1),
                    msg.id,
                    std::make_shared<StringMessageBody>("ECDH not completed")
                ));
                return;
            }

            auto msg_body = std::dynamic_pointer_cast<ByteArrayMessageBody>(msg.body);
            if (!msg_body || msg_body->data.size() < 2) {
                Logger::w(TAG, "Invalid PLAY message body");
                return;
            }

            // Parse client UDP port (big-endian)
            uint16_t client_udp_port = (static_cast<uint16_t>(msg_body->data[0]) << 8) |
                                        static_cast<uint16_t>(msg_body->data[1]);

            Logger::i(TAG, "Device [{}] requested PLAY on UDP port {}", config.name, client_udp_port);

            // Derive UDP audio key
            auto udp_key = derive_udp_audio_key(session_key);
            udp_audio_key = udp_key;

            // Create UDP socket for audio streaming
            try {
                udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
                if (udp_socket == INVALID_SOCKET) {
                    throw std::runtime_error("Failed to create UDP socket");
                }

                // Parse client address from TCP connection
                struct sockaddr_storage client_tcp_addr;
                socklen_t addr_len = sizeof(client_tcp_addr);
                if (getpeername(socket_fd, reinterpret_cast<struct sockaddr*>(&client_tcp_addr), &addr_len) != 0) {
                    close_udp_socket();
                    throw std::runtime_error("Failed to get client address");
                }

                // Set up client UDP address
                memset(&client_udp_addr, 0, sizeof(client_udp_addr));
                if (client_tcp_addr.ss_family == AF_INET) {
                    struct sockaddr_in* tcp_addr = reinterpret_cast<struct sockaddr_in*>(&client_tcp_addr);
                    struct sockaddr_in* udp_addr = reinterpret_cast<struct sockaddr_in*>(&client_udp_addr);
                    udp_addr->sin_family = AF_INET;
                    udp_addr->sin_addr = tcp_addr->sin_addr;  // Same IP as TCP connection
                    udp_addr->sin_port = htons(client_udp_port);  // Client specified port
                } else {
                    close_udp_socket();
                    throw std::runtime_error("IPv6 not supported yet");
                }

                // Initialize streaming state
                udp_streaming = true;
                udp_sequence_num = 0;
                audio_data_available = false;

                // Start UDP sending thread
                udp_send_thread = std::thread(&Device::udp_send_loop, this);

                Logger::i(TAG, "Device [{}] UDP socket created for streaming to port {}", config.name, client_udp_port);
            }
            catch (const std::exception& e) {
                Logger::e(TAG, "Failed to create UDP socket: " + std::string(e.what()));
                send_message(Message::build(
                    ProtocolMagic::ERROR,
                    queue_num_counter.fetch_add(1),
                    msg.id,
                    std::make_shared<StringMessageBody>("UDP socket creation failed: " + std::string(e.what()))
                ));
                return;
            }

            // Build PLAY_RESPONSE with audio info
            std::vector<uint8_t> response_body(12);
            auto audio_info = server_->get_audio_info();

            // UDP port (2 bytes) - using a dynamically bound port (0 for auto-assign)
            uint16_t server_udp_port = 0;  // Server uses client port for sending
            response_body[0] = (server_udp_port >> 8) & 0xFF;
            response_body[1] = server_udp_port & 0xFF;

            // Sample rate (4 bytes)
            response_body[2] = (audio_info.sample_rate >> 24) & 0xFF;
            response_body[3] = (audio_info.sample_rate >> 16) & 0xFF;
            response_body[4] = (audio_info.sample_rate >> 8) & 0xFF;
            response_body[5] = audio_info.sample_rate & 0xFF;

            // Bits (2 bytes)
            response_body[6] = (audio_info.bits >> 8) & 0xFF;
            response_body[7] = audio_info.bits & 0xFF;

            // Channels (2 bytes)
            response_body[8] = (audio_info.channels >> 8) & 0xFF;
            response_body[9] = audio_info.channels & 0xFF;

            // Format (2 bytes)
            response_body[10] = (audio_info.format >> 8) & 0xFF;
            response_body[11] = audio_info.format & 0xFF;

            send_message(Message::build(
                ProtocolMagic::PLAY_RESPONSE,
                queue_num_counter.fetch_add(1),
                msg.id,
                std::make_shared<ByteArrayMessageBody>(response_body)
            ).to_aes256gcm_encrypted_message(server_->get_sign_key(), session_key));

            Logger::i(TAG, "Device [{}] PLAY_RESPONSE sent", config.name);
            break;
        }
    case ProtocolMagic::STOP:
        {
            Logger::i(TAG, "Device [{}] requested STOP", config.name);

            // Stop UDP audio streaming and cleanup resources
            if (udp_streaming) {
                udp_streaming = false;

                // Wait for UDP send thread to finish
                if (udp_send_thread.joinable()) {
                    // Signal audio buffer to wake up waiting thread
                    {
                        std::lock_guard<std::mutex> lock(audio_buffer_mutex);
                        audio_data_available = true;
                    }
                    audio_buffer_cv.notify_all();
                    udp_send_thread.join();
                }

                // Close UDP socket
                close_udp_socket();

                // Clear audio buffer
                {
                    std::lock_guard<std::mutex> lock(audio_buffer_mutex);
                    audio_buffer.clear();
                    audio_data_available = false;
                }

                Logger::i(TAG, "Device [{}] UDP streaming stopped", config.name);
            }

            // Send STOP_RESPONSE with success status
            std::vector<uint8_t> response_body(1);
            response_body[0] = 0; // Success

            send_message(Message::build(
                ProtocolMagic::STOP_RESPONSE,
                queue_num_counter.fetch_add(1),
                msg.id,
                std::make_shared<ByteArrayMessageBody>(response_body)
            ).to_aes256gcm_encrypted_message(server_->get_sign_key(), session_key));

            Logger::i(TAG, "Device [{}] STOP_RESPONSE sent", config.name);
            break;
        }
    default:
        {
            // 将消息加入链表
            {
                std::lock_guard lock(message_queue_mutex);
                received_messages.push_back(msg);
            }
            message_cv.notify_all();

            // 调用回调
            std::lock_guard lock(callback_mutex);
            if (message_callback)
            {
                message_callback(msg);
            }
            break;
        }
    }
}

void Device::send_message(const Message& msg)
{
    check_connection();

    const auto data = msg.serialize(server_->get_sign_key());
    ssize_t sent = socket_send(data.data(), data.size());

    if (sent < 0 || static_cast<size_t>(sent) != data.size())
    {
        throw std::runtime_error("Failed to send message");
    }

    Logger::d(TAG, "Sent message: magic=" + std::string(to_string(msg.magic)) +
              " id=" + std::to_string(msg.id) + "\tdata=" + HEX_TOOL::to_hex(data.data(), data.size()));
}

void Device::set_message_callback(MessageCallback callback)
{
    std::lock_guard<std::mutex> lock(callback_mutex);
    message_callback = std::move(callback);
}

void Device::set_error_callback(ErrorCallback callback)
{
    std::lock_guard<std::mutex> lock(callback_mutex);
    error_callback = std::move(callback);
}

std::optional<Message> Device::wait_for_message(ProtocolMagic magic, int32_t msg_id, long timeout_ms)
{
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);

    std::unique_lock<std::mutex> lock(message_queue_mutex);

    while (true)
    {
        // 使用迭代器遍历链表，找到匹配的消息直接删除
        for (auto it = received_messages.begin(); it != received_messages.end(); ++it)
        {
            if (it->magic == magic && it->id == msg_id)
            {
                Message result = *it;
                received_messages.erase(it); // O(1) 删除
                return result;
            }
        }

        // 等待新消息或超时
        if (message_cv.wait_until(lock, deadline) == std::cv_status::timeout)
        {
            Logger::w(TAG, "Timeout waiting for message: magic=" + std::string(to_string(magic)) +
                      " id=" + std::to_string(msg_id));
            return std::nullopt;
        }
    }
}

void Device::ecdh(const Crypto::X25519& key_pair)
{
    check_connection();

    // 构建 ECDH 消息
    int32_t msg_id = get_next_message_id();
    auto public_key_bytes = key_pair.export_public_key();

    auto body = std::make_shared<ByteArrayMessageBody>(public_key_bytes);
    auto msg = Message::build(ProtocolMagic::ECDH, get_next_queue_num(), msg_id, body);

    // 发送消息
    send_message(msg);

    // 等待响应
    auto response = wait_for_message(ProtocolMagic::ECDH_RESPONSE, msg_id, msg_wait_timeout);
    if (!response)
    {
        throw std::runtime_error("Device [" + config.name + "] ECDH: no response received");
    }

    // 解析响应
    if (auto* byte_body = dynamic_cast<ByteArrayMessageBody*>(response->body.get()))
    {
        if (byte_body->data.size() == 32)
        {
            // 加载服务器公钥并派生共享密钥
            auto server_public_key = Crypto::X25519::load_public_key_from_mem(byte_body->data);
            std::vector<uint8_t> salt; // 空盐值
            auto shared_secret = key_pair.derive_shared_secret(server_public_key);

            // 复制到会话密钥
            if (shared_secret.size() >= 32)
            {
                std::copy(shared_secret.begin(), shared_secret.begin() + 32, session_key.begin());
                ecdh_completed = true;
                Logger::d(TAG, "Device [" + config.name + "] ECDH success");
            }
            else
            {
                throw std::runtime_error("Derived shared secret too short");
            }
        }
        else
        {
            throw std::runtime_error("Invalid ECDH response: incorrect key size");
        }
    }
    else
    {
        throw std::runtime_error("Invalid ECDH response: wrong body type");
    }
}

int32_t Device::get_next_message_id()
{
    return message_id_counter.fetch_add(1);
}

int32_t Device::get_next_queue_num()
{
    return queue_num_counter.fetch_add(1);
}

// UDP related method implementations

void Device::udp_send_loop()
{
    Logger::d(TAG, "Device [{}] UDP send thread started", config.name);

    constexpr size_t MAX_UDP_PAYLOAD = 1400; // Safe UDP payload size
    constexpr size_t AUDIO_CHUNK_SIZE = 1024; // Audio data chunk size per packet

    std::vector<uint8_t> packet_buffer;
    packet_buffer.reserve(MAX_UDP_PAYLOAD);

    try {
        while (udp_streaming) {
            std::unique_lock<std::mutex> lock(audio_buffer_mutex);

            // Wait for audio data or stop signal
            audio_buffer_cv.wait(lock, [this] {
                return audio_data_available || !udp_streaming;
            });

            if (!udp_streaming) {
                break;
            }

            // Process available audio data
            while (!audio_buffer.empty() && udp_streaming) {
                size_t chunk_size = std::min(audio_buffer.size(), AUDIO_CHUNK_SIZE);

                // Build UDP packet: [sequence_number(4)] + [encrypted_audio_data]
                packet_buffer.clear();

                // Add sequence number (big-endian)
                uint32_t seq = udp_sequence_num.fetch_add(1);
                packet_buffer.push_back((seq >> 24) & 0xFF);
                packet_buffer.push_back((seq >> 16) & 0xFF);
                packet_buffer.push_back((seq >> 8) & 0xFF);
                packet_buffer.push_back(seq & 0xFF);

                // Extract audio chunk
                std::vector<uint8_t> audio_chunk(audio_buffer.begin(), audio_buffer.begin() + chunk_size);
                audio_buffer.erase(audio_buffer.begin(), audio_buffer.begin() + chunk_size);

                // Encrypt audio data using UDP audio key
                auto encrypted_chunk = encrypt_audio_data(audio_chunk);
                packet_buffer.insert(packet_buffer.end(), encrypted_chunk.begin(), encrypted_chunk.end());

                // Release lock before sending
                lock.unlock();

                // Send UDP packet
                send_udp_packet(packet_buffer.data(), packet_buffer.size());

                // Reacquire lock for next iteration
                lock.lock();
            }

            if (audio_buffer.empty()) {
                audio_data_available = false;
            }
        }
    }
    catch (const std::exception& e) {
        Logger::e(TAG, "Exception in UDP send loop: " + std::string(e.what()));
    }

    Logger::d(TAG, "Device [{}] UDP send thread ended", config.name);
}

std::vector<uint8_t> Device::encrypt_audio_data(const std::vector<uint8_t>& plaintext)
{
    // Simple XOR encryption with UDP audio key (can be replaced with proper AES if needed)
    std::vector<uint8_t> encrypted = plaintext;
    for (size_t i = 0; i < encrypted.size(); ++i) {
        encrypted[i] ^= udp_audio_key[i % udp_audio_key.size()];
    }
    return encrypted;
}

void Device::send_udp_packet(const uint8_t* data, size_t len)
{
    if (udp_socket == INVALID_SOCKET || !udp_streaming) {
        return;
    }

    ssize_t sent = sendto(udp_socket,
                          reinterpret_cast<const char*>(data),
                          static_cast<int>(len),
                          0,
                          reinterpret_cast<const struct sockaddr*>(&client_udp_addr),
                          sizeof(struct sockaddr_in));

    if (sent < 0 || static_cast<size_t>(sent) != len) {
        Logger::w(TAG, "Failed to send UDP packet: sent={} expected={}", sent, len);
    }
}

void Device::close_udp_socket()
{
    if (udp_socket != INVALID_SOCKET) {
#ifdef _WIN32
        closesocket(udp_socket);
#else
        ::close(udp_socket);
#endif
        udp_socket = INVALID_SOCKET;
        Logger::d(TAG, "Device [{}] UDP socket closed", config.name);
    }
}

void Device::push_audio_data(const uint8_t* data, size_t len)
{
    if (!udp_streaming || len == 0) {
        return;
    }

    std::lock_guard<std::mutex> lock(audio_buffer_mutex);

    // Append new audio data to buffer
    audio_buffer.insert(audio_buffer.end(), data, data + len);
    audio_data_available = true;

    // Limit buffer size to prevent memory overflow
    constexpr size_t MAX_BUFFER_SIZE = 1024 * 1024; // 1MB
    if (audio_buffer.size() > MAX_BUFFER_SIZE) {
        size_t excess = audio_buffer.size() - MAX_BUFFER_SIZE;
        audio_buffer.erase(audio_buffer.begin(), audio_buffer.begin() + excess);
    }

    // Notify UDP send thread
    audio_buffer_cv.notify_one();
}
