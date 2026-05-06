#include "mantra.h"
#include "ble_adv_utils.h"

namespace fanesp::codecs {

const uint8_t MantraEncoder::FAMILY[4] = {0x12, 0x34, 0x56, 0x78};

std::optional<std::vector<uint8_t>> MantraEncoder::decrypt(const std::vector<uint8_t>& buffer) {
    if (buffer.size() < 7) return std::nullopt;
    // Seed = big-endian LE16 at bytes [2:4] (after prefix strip; passed as full _len bytes here)
    uint16_t seed = (static_cast<uint16_t>(buffer[2]) << 8) | buffer[3];
    auto tail = whiten16(std::vector<uint8_t>(buffer.begin() + 5, buffer.end()), seed);
    std::vector<uint8_t> out(buffer.begin(), buffer.begin() + 5);
    out.insert(out.end(), tail.begin(), tail.end());
    return out;
}

std::vector<uint8_t> MantraEncoder::encrypt(const std::vector<uint8_t>& decoded) {
    if (decoded.size() < 7) return {};
    uint16_t seed = (static_cast<uint16_t>(decoded[2]) << 8) | decoded[3];
    auto tail = whiten16(std::vector<uint8_t>(decoded.begin() + 5, decoded.end()), seed);
    std::vector<uint8_t> out(decoded.begin(), decoded.begin() + 5);
    out.insert(out.end(), tail.begin(), tail.end());
    return out;
}

bool MantraEncoder::convert_to_enc(const std::vector<uint8_t>& decoded,
                                    BleAdvEncCmd& enc_cmd, BleAdvConfig& conf) {
    // After prefix strip (2 bytes): [count_hi(0), count_lo(1), 0x06(2), cmd(3), fam(4-7), id_hi(8), id_lo(9),
    //                                 param(10), arg0(11), arg1(12), arg2(13), arg3(14), arg4(15)]
    if (decoded.size() < 16) return false;
    if (decoded[2] != 0x06) return false;
    if (decoded[4] != FAMILY[0] || decoded[5] != FAMILY[1] ||
        decoded[6] != FAMILY[2] || decoded[7] != FAMILY[3]) return false;

    uint16_t count    = (static_cast<uint16_t>(decoded[0]) << 8) | decoded[1];
    conf.index        = (count & 0xF000u) >> 12;
    conf.tx_count     = count & 0x0FFFu;
    conf.id           = (static_cast<uint32_t>(decoded[8]) << 8) | decoded[9];
    enc_cmd.cmd       = decoded[3];
    enc_cmd.param     = decoded[10];
    enc_cmd.arg0      = decoded[11];
    enc_cmd.arg1      = decoded[12];
    enc_cmd.arg2      = decoded[13];
    enc_cmd.arg3      = decoded[14];
    enc_cmd.arg4      = decoded[15];
    return true;
}

std::vector<uint8_t> MantraEncoder::convert_from_enc(const BleAdvEncCmd& enc_cmd,
                                                       const BleAdvConfig& conf) {
    uint16_t count = static_cast<uint16_t>(conf.tx_count) | (static_cast<uint16_t>(conf.index) << 12);
    return {
        static_cast<uint8_t>((count >> 8) & 0xFF),
        static_cast<uint8_t>(count & 0xFF),
        0x06,
        enc_cmd.cmd,
        FAMILY[0], FAMILY[1], FAMILY[2], FAMILY[3],
        static_cast<uint8_t>((conf.id >> 8) & 0xFF),
        static_cast<uint8_t>(conf.id & 0xFF),
        enc_cmd.param,
        enc_cmd.arg0,
        enc_cmd.arg1,
        enc_cmd.arg2,
        enc_cmd.arg3,
        enc_cmd.arg4,
    };
}

std::vector<Codec*> get_mantra_codecs() {
    static MantraEncoder codec_v0, codec_v1;
    static bool init = false;
    if (!init) {
        codec_v0.header({0x4E, 0x6F}).prefix({0x72, 0x0E}).ble(0x1A, 0xFF);
        codec_v1.header({0x4E, 0x6F}).prefix({0x72, 0x0F}).ble(0x1A, 0xFF);
        init = true;
    }
    return {&codec_v0, &codec_v1};
}

} // namespace fanesp::codecs
