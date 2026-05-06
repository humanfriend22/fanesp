#include "smartelfin.h"

namespace fanesp::codecs {

constexpr uint8_t SmartElfinEncoder::FIXED[4];

std::optional<std::vector<uint8_t>> SmartElfinEncoder::decrypt(const std::vector<uint8_t>& buffer) {
    if (buffer.size() < 8) return std::nullopt;
    if (buffer[4] != FIXED[0] || buffer[5] != FIXED[1] ||
        buffer[6] != FIXED[2] || buffer[7] != FIXED[3]) return std::nullopt;
    std::vector<uint8_t> out(buffer.begin(), buffer.begin() + 4);
    out.insert(out.end(), buffer.begin() + 8, buffer.end());
    return out;
}

std::vector<uint8_t> SmartElfinEncoder::encrypt(const std::vector<uint8_t>& decoded) {
    std::vector<uint8_t> out(decoded.begin(), decoded.begin() + 4);
    out.insert(out.end(), FIXED, FIXED + 4);
    out.insert(out.end(), decoded.begin() + 4, decoded.end());
    return out;
}

bool SmartElfinEncoder::convert_to_enc(const std::vector<uint8_t>& decoded,
                                        BleAdvEncCmd& enc_cmd, BleAdvConfig& conf) {
    if (decoded.size() < 8) return false;
    conf.id       = static_cast<uint32_t>(decoded[0])
                  | (static_cast<uint32_t>(decoded[1]) << 8)
                  | (static_cast<uint32_t>(decoded[2]) << 16);
    conf.tx_count = decoded[3];
    enc_cmd.param = decoded[4];
    enc_cmd.cmd   = decoded[5];
    enc_cmd.arg0  = decoded[6];
    enc_cmd.arg1  = decoded[7];
    return true;
}

std::vector<uint8_t> SmartElfinEncoder::convert_from_enc(const BleAdvEncCmd& enc_cmd,
                                                           const BleAdvConfig& conf) {
    return {
        static_cast<uint8_t>(conf.id & 0xFF),
        static_cast<uint8_t>((conf.id >> 8) & 0xFF),
        static_cast<uint8_t>((conf.id >> 16) & 0xFF),
        conf.tx_count,
        enc_cmd.param,
        enc_cmd.cmd,
        enc_cmd.arg0,
        enc_cmd.arg1,
    };
}

std::vector<Codec*> get_smartelfin_codecs() {
    static SmartElfinEncoder codec_se_v0;
    static bool init = false;
    if (!init) {
        codec_se_v0.header({0x57, 0x46, 0x54, 0x58}).ble(0x02, 0x07);
        init = true;
    }
    return {&codec_se_v0};
}

} // namespace fanesp::codecs
