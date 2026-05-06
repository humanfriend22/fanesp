#include "rw.h"
#include "ble_adv_utils.h"

namespace fanesp::codecs {

std::optional<std::vector<uint8_t>> RwEncoder::decrypt(const std::vector<uint8_t>& buffer) {
    if (buffer.size() < 18) return std::nullopt;
    auto decoded = reverse_all(whiten(buffer, 0x69));

    // Verify fixed marker bytes
    if (decoded[8]  != 0x4C || decoded[9]  != 0xFF ||
        decoded[10] != 0x00 || decoded[12] != 0x01 || decoded[14] != 0x02)
        return std::nullopt;

    // Verify CRC16-CCITT(seed=0x696B) over first 16 bytes, stored big-endian in bytes 16-17
    uint16_t expected_crc = (static_cast<uint16_t>(decoded[16]) << 8) | decoded[17];
    auto data16 = std::vector<uint8_t>(decoded.begin(), decoded.begin() + 16);
    if (crc16_ccitt(data16, 0x696Bu) != expected_crc) return std::nullopt;

    uint8_t pivot = decoded[11] ^ decoded[13] ^ decoded[15];
    return std::vector<uint8_t>{
        static_cast<uint8_t>(decoded[0]  ^ pivot),
        static_cast<uint8_t>(decoded[1]  ^ pivot),
        static_cast<uint8_t>(decoded[2]  ^ pivot ^ decoded[1]),
        static_cast<uint8_t>(decoded[3]  ^ pivot ^ decoded[1]),
        static_cast<uint8_t>(decoded[4]  ^ pivot ^ decoded[1]),
        static_cast<uint8_t>(decoded[5]  ^ pivot ^ decoded[2]),
        static_cast<uint8_t>(decoded[6]  ^ pivot ^ decoded[2]),
        static_cast<uint8_t>(decoded[7]  ^ pivot ^ decoded[2]),
        static_cast<uint8_t>(decoded[11] ^ pivot ^ decoded[5]),
        static_cast<uint8_t>(decoded[13] ^ pivot ^ decoded[5]),
        pivot,
    };
}

std::vector<uint8_t> RwEncoder::encrypt(const std::vector<uint8_t>& buffer) {
    if (buffer.size() < 11) return {};
    uint8_t b12 = buffer[1] ^ buffer[2];
    std::vector<uint8_t> encoded = {
        static_cast<uint8_t>(buffer[0] ^ buffer[10]),
        static_cast<uint8_t>(buffer[1] ^ buffer[10]),
        static_cast<uint8_t>(buffer[2] ^ buffer[1]),
        static_cast<uint8_t>(buffer[3] ^ buffer[1]),
        static_cast<uint8_t>(buffer[4] ^ buffer[1]),
        static_cast<uint8_t>(buffer[5] ^ b12 ^ buffer[10]),
        static_cast<uint8_t>(buffer[6] ^ b12 ^ buffer[10]),
        static_cast<uint8_t>(buffer[7] ^ b12 ^ buffer[10]),
        0x4C, 0xFF, 0x00,
        static_cast<uint8_t>(buffer[8] ^ b12),
        0x01,
        static_cast<uint8_t>(buffer[9] ^ b12),
        0x02,
        static_cast<uint8_t>(buffer[8] ^ buffer[9] ^ buffer[10]),
    };
    uint16_t crc = crc16_ccitt(encoded, 0x696Bu);
    encoded.push_back(static_cast<uint8_t>((crc >> 8) & 0xFF));
    encoded.push_back(static_cast<uint8_t>(crc & 0xFF));
    return whiten(reverse_all(encoded), 0x69);
}

bool RwEncoder::convert_to_enc(const std::vector<uint8_t>& decoded,
                                BleAdvEncCmd& enc_cmd, BleAdvConfig& conf) {
    if (decoded.size() < 11) return false;
    conf.id       = static_cast<uint32_t>(decoded[2])
                  | (static_cast<uint32_t>(decoded[3]) << 8)
                  | (static_cast<uint32_t>(decoded[4]) << 16)
                  | (static_cast<uint32_t>(decoded[5]) << 24);
    conf.index    = decoded[6];
    conf.tx_count = decoded[1];
    conf.seed     = decoded[10];
    enc_cmd.cmd   = decoded[0];
    enc_cmd.arg0  = decoded[7];
    enc_cmd.arg1  = decoded[8];
    enc_cmd.arg2  = decoded[9];
    return true;
}

std::vector<uint8_t> RwEncoder::convert_from_enc(const BleAdvEncCmd& enc_cmd,
                                                   const BleAdvConfig& conf) {
    return {
        enc_cmd.cmd,
        conf.tx_count,
        static_cast<uint8_t>(conf.id & 0xFF),
        static_cast<uint8_t>((conf.id >> 8) & 0xFF),
        static_cast<uint8_t>((conf.id >> 16) & 0xFF),
        static_cast<uint8_t>((conf.id >> 24) & 0xFF),
        conf.index,
        enc_cmd.arg0,
        enc_cmd.arg1,
        enc_cmd.arg2,
        static_cast<uint8_t>(conf.seed & 0xFF),
    };
}

std::vector<Codec*> get_rw_codecs() {
    static RwEncoder codec_rwmix;
    static bool init = false;
    if (!init) {
        codec_rwmix
            .header({0xDD, 0xB2, 0xDA, 0x6C, 0x9F, 0x01, 0x7A, 0x34})
            .ble(0x1A, 0xFF);
        init = true;
    }
    return {&codec_rwmix};
}

} // namespace fanesp::codecs
