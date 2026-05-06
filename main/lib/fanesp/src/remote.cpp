#include "remote.h"

namespace fanesp::codecs {

std::optional<std::vector<uint8_t>> RemoteEncoder::decrypt(const std::vector<uint8_t>& buffer) {
    if (buffer.size() < 8) return std::nullopt;
    uint8_t sum = 0;
    for (size_t i = 0; i < 7; i++) sum += buffer[i];
    if (sum != buffer[7]) return std::nullopt;
    return buffer;
}

std::vector<uint8_t> RemoteEncoder::encrypt(const std::vector<uint8_t>& decoded) {
    std::vector<uint8_t> out = decoded;
    uint8_t sum = 0;
    for (uint8_t b : decoded) sum += b;
    out.push_back(sum);
    return out;
}

bool RemoteEncoder::convert_to_enc(const std::vector<uint8_t>& decoded,
                                    BleAdvEncCmd& enc_cmd, BleAdvConfig& conf) {
    if (decoded.size() < 8) return false;
    conf.tx_count = decoded[6];
    conf.id       = static_cast<uint32_t>(decoded[1])
                  | (static_cast<uint32_t>(decoded[2]) << 8)
                  | (static_cast<uint32_t>(decoded[3]) << 16)
                  | (static_cast<uint32_t>(decoded[4]) << 24);
    enc_cmd.cmd   = decoded[5] & 0x3Fu;
    enc_cmd.arg0  = decoded[0];
    enc_cmd.arg1  = decoded[5] & 0xC0u;
    return true;
}

std::vector<uint8_t> RemoteEncoder::convert_from_enc(const BleAdvEncCmd& enc_cmd,
                                                       const BleAdvConfig& conf) {
    return {
        enc_cmd.arg0,
        static_cast<uint8_t>(conf.id & 0xFF),
        static_cast<uint8_t>((conf.id >> 8) & 0xFF),
        static_cast<uint8_t>((conf.id >> 16) & 0xFF),
        static_cast<uint8_t>((conf.id >> 24) & 0xFF),
        static_cast<uint8_t>(enc_cmd.cmd | enc_cmd.arg1),
        conf.tx_count,
    };
}

std::vector<Codec*> get_remote_codecs() {
    static RemoteEncoder codec_remote_v4;
    static bool init = false;
    if (!init) {
        codec_remote_v4.header({0xF0, 0xFF}).ble(0x1A, 0xFF);
        init = true;
    }
    return {&codec_remote_v4};
}

} // namespace fanesp::codecs
