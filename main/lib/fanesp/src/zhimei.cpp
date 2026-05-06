#include "zhimei.h"
#include "ble_adv_utils.h"

namespace fanesp::codecs {

// ─── ZhimeiEncoderV0 ──────────────────────────────────────────────────────────

std::optional<std::vector<uint8_t>> ZhimeiEncoderV0::decrypt(const std::vector<uint8_t>& buffer) {
    if (buffer.size() < 9) return std::nullopt;
    uint8_t sum = 0;
    for (size_t i = 0; i + 1 < buffer.size(); i++) sum += buffer[i];
    for (uint8_t h : _header) sum += h;
    if (sum != buffer.back()) return std::nullopt;
    return buffer;
}

std::vector<uint8_t> ZhimeiEncoderV0::encrypt(const std::vector<uint8_t>& buffer) {
    uint8_t sum = 0;
    for (uint8_t b : buffer) sum += b;
    for (uint8_t h : _header) sum += h;
    std::vector<uint8_t> out(buffer);
    out.push_back(sum);
    return out;
}

bool ZhimeiEncoderV0::convert_to_enc(const std::vector<uint8_t>& decoded,
                                       BleAdvEncCmd& enc_cmd, BleAdvConfig& conf) {
    // [index(0), tx_count(1), id_lo(2), id_hi(3), cmd(4), arg0(5), arg1(6), arg2(7)]
    if (decoded.size() < 8) return false;
    conf.index    = decoded[0];
    conf.tx_count = decoded[1];
    conf.id       = static_cast<uint32_t>(decoded[2]) | (static_cast<uint32_t>(decoded[3]) << 8);
    enc_cmd.cmd   = decoded[4];
    enc_cmd.arg0  = decoded[5];
    enc_cmd.arg1  = decoded[6];
    enc_cmd.arg2  = decoded[7];
    return true;
}

std::vector<uint8_t> ZhimeiEncoderV0::convert_from_enc(const BleAdvEncCmd& enc_cmd,
                                                         const BleAdvConfig& conf) {
    return {
        conf.index,
        conf.tx_count,
        static_cast<uint8_t>(conf.id & 0xFF),
        static_cast<uint8_t>((conf.id >> 8) & 0xFF),
        enc_cmd.cmd,
        enc_cmd.arg0,
        enc_cmd.arg1,
        enc_cmd.arg2,
    };
}

// ─── ZhimeiEncoderV1 ──────────────────────────────────────────────────────────

std::optional<std::vector<uint8_t>> ZhimeiEncoderV1::decrypt(const std::vector<uint8_t>& buffer) {
    // buffer.size() == _header_start_pos + _len == hsp + 16
    size_t hsp = static_cast<size_t>(_header_start_pos);
    if (buffer.size() < hsp + 16) return std::nullopt;

    auto decoded = zhimei_unapply_matrix(
        std::vector<uint8_t>(buffer.begin() + hsp, buffer.end()), 6);

    // CRC16-CCITT(seed=0) over first 13 bytes, stored LE in bytes [14:16]
    uint16_t expected = static_cast<uint16_t>(decoded[14]) | (static_cast<uint16_t>(decoded[15]) << 8);
    uint16_t computed = crc16_ccitt(std::vector<uint8_t>(decoded.begin(), decoded.begin() + 13), 0);
    if (computed != expected) return std::nullopt;

    decoded.resize(14);

    if (decoded[7] != 0xB4) {
        auto tail = zhimei_unapply_matrix(
            std::vector<uint8_t>(decoded.begin() + 9, decoded.end()), 10);
        decoded.resize(9);
        decoded.insert(decoded.end(), tail.begin(), tail.end());
    }

    if (decoded[2] != decoded[10]) return std::nullopt;
    if (decoded[0] != 0xFF)        return std::nullopt;
    if (decoded[9] != 0xFF)        return std::nullopt;
    for (size_t i = 0; i < hsp; i++) {
        if (buffer[i] != decoded[2 + i]) return std::nullopt;
    }

    return decoded;
}

std::vector<uint8_t> ZhimeiEncoderV1::encrypt(const std::vector<uint8_t>& buffer) {
    // buffer = prefix (empty) + convert_from_enc output = 14 bytes
    size_t hsp = static_cast<size_t>(_header_start_pos);
    std::vector<uint8_t> data(buffer);

    if (data[7] != 0xB4) {
        auto tail = zhimei_apply_matrix(
            std::vector<uint8_t>(data.begin() + 9, data.end()), 10);
        data.resize(9);
        data.insert(data.end(), tail.begin(), tail.end());
    }

    // CRC over first 13 bytes, append LE
    uint16_t crc = crc16_ccitt(
        std::vector<uint8_t>(data.begin(), data.end() - 1), 0);
    data.push_back(crc & 0xFF);
    data.push_back((crc >> 8) & 0xFF);

    auto mat = zhimei_apply_matrix(data, 6);

    // Pre-header bytes: buffer[2 .. 2+hsp), then matrix result
    std::vector<uint8_t> out(buffer.begin() + 2,
                              buffer.begin() + 2 + static_cast<ptrdiff_t>(hsp));
    out.insert(out.end(), mat.begin(), mat.end());
    return out;
}

bool ZhimeiEncoderV1::convert_to_enc(const std::vector<uint8_t>& decoded,
                                       BleAdvEncCmd& enc_cmd, BleAdvConfig& conf) {
    // After prefix strip (prefix is empty for V1):
    // [0xFF(0), seed(1), tx_count(2), id_lo(3), id_hi(4), 0(5), 0(6), cmd(7),
    //  index(8), 0xFF(9), tx_count(10), arg0(11), arg1(12), arg2(13)]
    if (decoded.size() < 14) return false;
    conf.seed     = decoded[1];
    conf.tx_count = decoded[2];
    conf.id       = static_cast<uint32_t>(decoded[3])
                  | (static_cast<uint32_t>(decoded[4]) << 8)
                  | (static_cast<uint32_t>(decoded[5]) << 16)
                  | (static_cast<uint32_t>(decoded[6]) << 24);
    conf.index    = decoded[8];
    enc_cmd.cmd   = decoded[7];
    enc_cmd.arg0  = decoded[11];
    enc_cmd.arg1  = decoded[12];
    enc_cmd.arg2  = decoded[13];
    return true;
}

std::vector<uint8_t> ZhimeiEncoderV1::convert_from_enc(const BleAdvEncCmd& enc_cmd,
                                                         const BleAdvConfig& conf) {
    uint32_t uid = conf.id & 0xFFFF;
    return {
        0xFF,
        static_cast<uint8_t>(conf.seed & 0xFF),
        conf.tx_count,
        static_cast<uint8_t>(uid & 0xFF),
        static_cast<uint8_t>((uid >> 8) & 0xFF),
        0x00,
        0x00,
        enc_cmd.cmd,
        conf.index,
        0xFF,
        conf.tx_count,
        enc_cmd.arg0,
        enc_cmd.arg1,
        enc_cmd.arg2,
    };
}

// ─── ZhimeiEncoderV2 ──────────────────────────────────────────────────────────

static uint16_t zhimei_v2_crc16(const std::vector<uint8_t>& buf) {
    auto rev    = reverse_all(buf);
    uint16_t pre = crc16_ccitt(rev, 0xFFFF);
    return static_cast<uint16_t>(
        0xFFFFu ^ ((static_cast<uint16_t>(reverse_byte(pre & 0xFF)) << 8) |
                    reverse_byte(static_cast<uint8_t>(pre >> 8))));
}

std::optional<std::vector<uint8_t>> ZhimeiEncoderV2::decrypt(const std::vector<uint8_t>& buffer) {
    if (buffer.size() < 13) return std::nullopt;
    auto decoded = whiten(buffer, 0x48);
    uint16_t expected = static_cast<uint16_t>(decoded[11]) | (static_cast<uint16_t>(decoded[12]) << 8);
    if (zhimei_v2_crc16(std::vector<uint8_t>(decoded.begin(), decoded.end() - 2)) != expected)
        return std::nullopt;
    decoded.resize(11);
    return decoded;
}

std::vector<uint8_t> ZhimeiEncoderV2::encrypt(const std::vector<uint8_t>& buffer) {
    std::vector<uint8_t> out(buffer);
    uint16_t crc = zhimei_v2_crc16(out);
    out.push_back(crc & 0xFF);
    out.push_back((crc >> 8) & 0xFF);
    return whiten(out, 0x48);
}

bool ZhimeiEncoderV2::convert_to_enc(const std::vector<uint8_t>& decoded,
                                       BleAdvEncCmd& enc_cmd, BleAdvConfig& conf) {
    // After prefix strip ({0x33,0xAA,0x55}): 8 bytes
    if (decoded.size() < 8) return false;
    uint8_t pivot = decoded[0] ^ decoded[1] ^ decoded[6] ^ decoded[7];
    std::vector<uint8_t> d;
    d.reserve(8);
    for (uint8_t b : decoded) d.push_back(b ^ pivot);

    conf.index    = d[2];
    conf.tx_count = static_cast<uint8_t>(d[6] ^ d[0]);
    conf.id       = static_cast<uint32_t>(d[5]) | (static_cast<uint32_t>(d[0]) << 8);
    enc_cmd.cmd   = d[4];
    enc_cmd.arg0  = d[1];
    enc_cmd.arg1  = d[3];
    enc_cmd.arg2  = static_cast<uint8_t>(d[7] ^ d[1]);
    return true;
}

std::vector<uint8_t> ZhimeiEncoderV2::convert_from_enc(const BleAdvEncCmd& enc_cmd,
                                                         const BleAdvConfig& conf) {
    uint8_t uid_lo = static_cast<uint8_t>(conf.id & 0xFF);   // decoded[5] = low byte
    uint8_t uid_hi = static_cast<uint8_t>((conf.id >> 8) & 0xFF); // decoded[0] = high byte
    std::vector<uint8_t> pre = {
        uid_hi,
        enc_cmd.arg0,
        conf.index,
        enc_cmd.arg1,
        enc_cmd.cmd,
        uid_lo,
        static_cast<uint8_t>(conf.tx_count ^ uid_hi),
        static_cast<uint8_t>(enc_cmd.arg0 ^ enc_cmd.arg2),
    };
    uint8_t pivot = pre[0] ^ pre[1] ^ pre[6] ^ pre[7];
    for (uint8_t& b : pre) b ^= pivot;
    return pre;
}

// ─── Factory ──────────────────────────────────────────────────────────────────

std::vector<Codec*> get_zhimei_codecs() {
    static ZhimeiEncoderV0 fan_v0;
    static ZhimeiEncoderV1 fan_v1, v1, fan_vr1, fan_v1b, v1b;
    static ZhimeiEncoderV2 v2;
    static bool init = false;
    if (!init) {
        fan_v0.header({0x55}).ble(0x19, 0x03);
        fan_v1.header({0x48, 0x46, 0x4B, 0x4A}).ble(0x1A, 0x03);
        v1.header({0x48, 0x46, 0x4B, 0x4A}).ble(0x1A, 0x03);
        // Remote variant: 3 pre-header bytes, then 4-byte header
        fan_vr1.header({0x48, 0x46, 0x4B, 0x4A}, 3).ble(0x1A, 0xFF);
        // Variants with 3 zero bytes prepended to the header
        fan_v1b.header({0x00, 0x00, 0x00, 0x48, 0x46, 0x4B, 0x4A}).ble(0x1A, 0xFF);
        v1b.header({0x58, 0x55, 0x18, 0x48, 0x46, 0x4B, 0x4A}).ble(0x1A, 0xFF);
        v2.header({0xF9, 0x08, 0x49}).prefix({0x33, 0xAA, 0x55}).ble(0x1A, 0x03);
        init = true;
    }
    return {&fan_v0, &fan_v1, &v1, &fan_vr1, &fan_v1b, &v1b, &v2};
}

} // namespace fanesp::codecs
