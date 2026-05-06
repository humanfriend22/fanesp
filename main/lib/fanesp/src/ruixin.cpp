#include "ruixin.h"

namespace fanesp::codecs {

std::optional<std::vector<uint8_t>> RuiXinEncoder::decrypt(const std::vector<uint8_t>& buffer) {
    if (buffer.size() < 16) return std::nullopt;
    std::vector<uint8_t> buf(buffer);
    // De-obfuscate: subtract seed byte and position index from bytes [2:16]
    for (int i = 0; i < 14; i++) {
        buf[2 + i] = static_cast<uint8_t>((static_cast<int>(buf[2 + i]) - buf[0] - i + 512) % 256);
    }
    // Verify checksum: sum(buf[2:15]) & 0xFF == buf[15]
    uint8_t sum = 0;
    for (int i = 2; i < 15; i++) sum += buf[i];
    if (sum != buf[15]) return std::nullopt;
    // Return only meaningful bytes [0:10]
    return std::vector<uint8_t>(buf.begin(), buf.begin() + 10);
}

std::vector<uint8_t> RuiXinEncoder::encrypt(const std::vector<uint8_t>& decoded) {
    // Pad to 16 bytes with zeros
    std::vector<uint8_t> buf(decoded);
    buf.resize(16, 0x00);
    // Checksum: sum(buf[2:15]) & 0xFF
    uint8_t sum = 0;
    for (int i = 2; i < 15; i++) sum += buf[i];
    buf[15] = sum;
    // Obfuscate: add seed byte and position to each byte in [2:16]
    for (int i = 0; i < 14; i++) {
        buf[2 + i] = static_cast<uint8_t>((static_cast<int>(buf[2 + i]) + buf[0] + i) % 256);
    }
    return buf;
}

bool RuiXinEncoder::convert_to_enc(const std::vector<uint8_t>& decoded,
                                    BleAdvEncCmd& enc_cmd, BleAdvConfig& conf) {
    if (decoded.size() < 10) return false;
    conf.seed     = decoded[0];
    conf.tx_count = decoded[1];
    conf.id       = static_cast<uint32_t>(decoded[2])
                  | (static_cast<uint32_t>(decoded[3]) << 8)
                  | (static_cast<uint32_t>(decoded[4]) << 16)
                  | (static_cast<uint32_t>(decoded[5]) << 24);
    enc_cmd.cmd   = decoded[6];
    enc_cmd.arg0  = decoded[7];
    enc_cmd.arg1  = decoded[8];
    enc_cmd.arg2  = decoded[9];
    return true;
}

std::vector<uint8_t> RuiXinEncoder::convert_from_enc(const BleAdvEncCmd& enc_cmd,
                                                       const BleAdvConfig& conf) {
    return {
        static_cast<uint8_t>(conf.seed & 0xFF),
        conf.tx_count,
        static_cast<uint8_t>(conf.id & 0xFF),
        static_cast<uint8_t>((conf.id >> 8) & 0xFF),
        static_cast<uint8_t>((conf.id >> 16) & 0xFF),
        static_cast<uint8_t>((conf.id >> 24) & 0xFF),
        enc_cmd.cmd,
        enc_cmd.arg0,
        enc_cmd.arg1,
        enc_cmd.arg2,
    };
}

std::vector<Codec*> get_ruixin_codecs() {
    static RuiXinEncoder codec_rx_v0;
    static bool init = false;
    if (!init) {
        codec_rx_v0
            .header({0xFF, 0xFF, 0x01, 0x02, 0x03, 0x04, 0x69, 0x72, 0x36, 0x0E})
            .ble(0x00, 0xFF);
        init = true;
    }
    return {&codec_rx_v0};
}

} // namespace fanesp::codecs
