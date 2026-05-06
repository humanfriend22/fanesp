#include "zhijia.h"
#include "ble_adv_utils.h"

namespace fanesp::codecs {

// ─── Pivot helpers ────────────────────────────────────────────────────────────

// xor_mode: if pivot is even, XOR with 0xFF (ensures pivot is always odd).
template<size_t N>
static uint8_t compute_pivot(const std::vector<uint8_t>& buf,
                              const size_t (&idx)[N], bool xor_mode) {
    uint8_t piv = 0;
    for (size_t i : idx) piv ^= buf[i];
    if (xor_mode && (piv & 1) == 0) piv ^= 0xFF;
    return piv;
}

template<size_t N>
static std::vector<uint8_t> apply_pivot(std::vector<uint8_t> buf,
                                         const size_t (&idx)[N], bool xor_mode) {
    uint8_t piv = compute_pivot(buf, idx, xor_mode);
    for (uint8_t& b : buf) b ^= piv;
    return buf;
}

static constexpr size_t V0_IDX[4] = {0, 1, 6, 7};
static constexpr size_t V1_IDX[6] = {2, 4, 9, 12, 13, 15};
static constexpr size_t V2_IDX[6] = {3, 7, 11, 12, 13, 15};

// ─── V1/V2/Remote shared convert helpers ──────────────────────────────────────

// Extract fields from a 17-byte post-pivot decoded buffer.
// Stores extracted MAC in conf.aux_id (no MAC verification for discovery compatibility).
static bool common_convert_to_enc_v1(const std::vector<uint8_t>& d,
                                      BleAdvEncCmd& enc_cmd, BleAdvConfig& conf) {
    if (d.size() < 17) return false;
    conf.aux_id   = static_cast<uint32_t>(d[7])
                  | (static_cast<uint32_t>(d[10]) << 8)
                  | (static_cast<uint32_t>(static_cast<uint8_t>(d[13] ^ d[4])) << 16);
    conf.id       = static_cast<uint32_t>(d[2])
                  | (static_cast<uint32_t>(static_cast<uint8_t>(d[12] ^ d[2])) << 8)
                  | (static_cast<uint32_t>(static_cast<uint8_t>(d[15] ^ d[9])) << 16);
    conf.index    = d[6];
    conf.tx_count = d[4];
    enc_cmd.cmd   = d[9];
    enc_cmd.arg0  = d[0];
    enc_cmd.arg1  = d[3];
    enc_cmd.arg2  = d[5];
    return true;
}

// Build the 17-element pre-pivot array shared by V1, V2, and Remote.
static std::vector<uint8_t> common_convert_from_enc_v1(const BleAdvEncCmd& enc_cmd,
                                                        const BleAdvConfig& conf) {
    uint8_t u0 = static_cast<uint8_t>(conf.id & 0xFF);
    uint8_t u1 = static_cast<uint8_t>((conf.id >> 8) & 0xFF);
    uint8_t u2 = static_cast<uint8_t>((conf.id >> 16) & 0xFF);
    uint8_t m0 = static_cast<uint8_t>(conf.aux_id & 0xFF);
    uint8_t m1 = static_cast<uint8_t>((conf.aux_id >> 8) & 0xFF);
    uint8_t m2 = static_cast<uint8_t>((conf.aux_id >> 16) & 0xFF);

    uint8_t key = enc_cmd.cmd ^ enc_cmd.arg0 ^ enc_cmd.arg1 ^ enc_cmd.arg2
                ^ u0 ^ u1 ^ u2 ^ conf.tx_count ^ conf.index ^ m0 ^ m1 ^ m2;

    return {
        enc_cmd.arg0,                                // [0]
        key,                                          // [1]
        u0,                                           // [2]
        enc_cmd.arg1,                                 // [3]
        conf.tx_count,                                // [4]
        enc_cmd.arg2,                                 // [5]
        conf.index,                                   // [6]
        m0,                                           // [7]
        0x00,                                         // [8]
        enc_cmd.cmd,                                  // [9]
        m1,                                           // [10]
        0x00,                                         // [11]
        static_cast<uint8_t>(u1 ^ u0),               // [12]
        static_cast<uint8_t>(m2 ^ conf.tx_count),    // [13]
        0x00,                                         // [14] — overridden by callers
        static_cast<uint8_t>(u2 ^ enc_cmd.cmd),      // [15]
        0x00,                                         // [16]
    };
}

// ─── ZhijiaEncoderV0 ─────────────────────────────────────────────────────────

std::optional<std::vector<uint8_t>> ZhijiaEncoderV0::decrypt(const std::vector<uint8_t>& buffer) {
    if (buffer.size() < 13) return std::nullopt;
    auto decoded = whiten(whiten(buffer, 0x37), 0x7F);
    uint16_t expected = static_cast<uint16_t>(decoded[11]) | (static_cast<uint16_t>(decoded[12]) << 8);
    if (crc16_le(std::vector<uint8_t>(decoded.begin(), decoded.end() - 2), 0) != expected)
        return std::nullopt;
    decoded.resize(11);
    return decoded;
}

std::vector<uint8_t> ZhijiaEncoderV0::encrypt(const std::vector<uint8_t>& buffer) {
    // buffer = prefix(3) + pivoted_payload(8) = 11 bytes.
    // Pivot is already applied in convert_from_enc; just add CRC and double-whiten.
    std::vector<uint8_t> out(buffer);
    uint16_t crc = crc16_le(out, 0);
    out.push_back(crc & 0xFF);
    out.push_back((crc >> 8) & 0xFF);
    return whiten(whiten(out, 0x7F), 0x37);
}

bool ZhijiaEncoderV0::convert_to_enc(const std::vector<uint8_t>& decoded,
                                       BleAdvEncCmd& enc_cmd, BleAdvConfig& conf) {
    // decoded = 8 bytes after prefix strip {0x08,0x80,0x98}
    if (decoded.size() < 8) return false;
    auto d = apply_pivot(decoded, V0_IDX, false);
    conf.id        = static_cast<uint32_t>(d[0]) | (static_cast<uint32_t>(d[5]) << 8);
    conf.index     = d[2];
    conf.tx_count  = static_cast<uint8_t>(d[0] ^ d[6]);
    enc_cmd.cmd    = d[4];
    enc_cmd.arg0   = d[1];
    enc_cmd.arg1   = d[3];
    enc_cmd.arg2   = static_cast<uint8_t>(d[1] ^ d[7]);
    return true;
}

std::vector<uint8_t> ZhijiaEncoderV0::convert_from_enc(const BleAdvEncCmd& enc_cmd,
                                                         const BleAdvConfig& conf) {
    uint8_t u0 = static_cast<uint8_t>(conf.id & 0xFF);
    uint8_t u1 = static_cast<uint8_t>((conf.id >> 8) & 0xFF);
    std::vector<uint8_t> pre = {
        u0,
        enc_cmd.arg0,
        conf.index,
        enc_cmd.arg1,
        enc_cmd.cmd,
        u1,
        static_cast<uint8_t>(u0 ^ conf.tx_count),
        static_cast<uint8_t>(enc_cmd.arg0 ^ enc_cmd.arg2),
    };
    return apply_pivot(pre, V0_IDX, false);
}

// ─── ZhijiaEncoderV1 ─────────────────────────────────────────────────────────

std::optional<std::vector<uint8_t>> ZhijiaEncoderV1::decrypt(const std::vector<uint8_t>& buffer) {
    if (buffer.size() < 23) return std::nullopt;
    auto decoded = whiten(buffer, 0x37);
    uint16_t expected = static_cast<uint16_t>(decoded[21]) | (static_cast<uint16_t>(decoded[22]) << 8);
    if (crc16_le(std::vector<uint8_t>(decoded.begin(), decoded.end() - 2), 0) != expected)
        return std::nullopt;
    decoded.resize(21);
    return decoded;
}

std::vector<uint8_t> ZhijiaEncoderV1::encrypt(const std::vector<uint8_t>& buffer) {
    // buffer = prefix(4) + pivoted_payload(17) = 21 bytes.
    // Pivot already applied in convert_from_enc; just add CRC and whiten.
    std::vector<uint8_t> out(buffer);
    uint16_t crc = crc16_le(out, 0);
    out.push_back(crc & 0xFF);
    out.push_back((crc >> 8) & 0xFF);
    return whiten(out, 0x37);
}

bool ZhijiaEncoderV1::convert_to_enc(const std::vector<uint8_t>& decoded,
                                       BleAdvEncCmd& enc_cmd, BleAdvConfig& conf) {
    // decoded = 17 bytes (after prefix strip of 4 bytes, e.g. {0x55,0x08,0x80,0x98})
    if (decoded.size() < 17) return false;
    auto d = apply_pivot(decoded, V1_IDX, true);
    // V1 structural constraints
    if (d[8] != 0x00 || d[11] != 0x00 || d[7] != d[14]) return false;
    return common_convert_to_enc_v1(d, enc_cmd, conf);
}

std::vector<uint8_t> ZhijiaEncoderV1::convert_from_enc(const BleAdvEncCmd& enc_cmd,
                                                         const BleAdvConfig& conf) {
    auto oarray = common_convert_from_enc_v1(enc_cmd, conf);
    oarray[14] = oarray[7];
    return apply_pivot(oarray, V1_IDX, true);
}

// ─── ZhijiaEncoderV2 ─────────────────────────────────────────────────────────

std::optional<std::vector<uint8_t>> ZhijiaEncoderV2::decrypt(const std::vector<uint8_t>& buffer) {
    if (buffer.size() < 24) return std::nullopt;
    auto buf1 = whiten(buffer, 0x6F);
    auto w22  = whiten(std::vector<uint8_t>(buf1.begin(), buf1.end() - 2), 0xD3);
    std::vector<uint8_t> buf2(w22);
    buf2.push_back(buf1[22]);
    buf2.push_back(buf1[23]);
    for (size_t i = 17; i < 24; i++) {
        if (buf2[i] != 0x00) return std::nullopt;
    }
    return std::vector<uint8_t>(buf2.begin(), buf2.begin() + 17);
}

std::vector<uint8_t> ZhijiaEncoderV2::encrypt(const std::vector<uint8_t>& buffer) {
    // buffer = no prefix + pivoted_payload(17) = 17 bytes.
    std::vector<uint8_t> buf(buffer);
    buf.resize(24, 0x00);
    auto w22 = whiten(std::vector<uint8_t>(buf.begin(), buf.begin() + 22), 0xD3);
    w22.push_back(buf[22]);
    w22.push_back(buf[23]);
    return whiten(w22, 0x6F);
}

bool ZhijiaEncoderV2::convert_to_enc(const std::vector<uint8_t>& decoded,
                                       BleAdvEncCmd& enc_cmd, BleAdvConfig& conf) {
    // decoded = 17 bytes (no prefix for V2)
    if (decoded.size() < 17) return false;
    auto d = apply_pivot(decoded, V2_IDX, true);
    // V2 structural constraints
    if (d[8]  != static_cast<uint8_t>(d[2] ^ d[3] ^ d[4] ^ d[7])) return false;
    if (d[11] != 0x00)                                               return false;
    if (d[14] != static_cast<uint8_t>(d[2] ^ d[3] ^ d[4] ^ d[9])) return false;
    return common_convert_to_enc_v1(d, enc_cmd, conf);
}

std::vector<uint8_t> ZhijiaEncoderV2::convert_from_enc(const BleAdvEncCmd& enc_cmd,
                                                         const BleAdvConfig& conf) {
    auto oarray = common_convert_from_enc_v1(enc_cmd, conf);
    oarray[1] ^= oarray[9];
    oarray[8]  = oarray[2] ^ oarray[3] ^ oarray[4] ^ oarray[7];
    oarray[14] = oarray[2] ^ oarray[3] ^ oarray[4] ^ oarray[9];
    return apply_pivot(oarray, V2_IDX, true);
}

// ─── ZhijiaEncoderRemote ─────────────────────────────────────────────────────

std::optional<std::vector<uint8_t>> ZhijiaEncoderRemote::decrypt(const std::vector<uint8_t>& buffer) {
    return buffer;
}

std::vector<uint8_t> ZhijiaEncoderRemote::encrypt(const std::vector<uint8_t>& buffer) {
    return buffer;
}

bool ZhijiaEncoderRemote::convert_to_enc(const std::vector<uint8_t>& decoded,
                                          BleAdvEncCmd& enc_cmd, BleAdvConfig& conf) {
    if (decoded.size() < 17) return false;
    // XOR all bytes by decoded[5], then apply V1 pivot
    uint8_t xk = decoded[5];
    std::vector<uint8_t> d;
    d.reserve(decoded.size());
    for (uint8_t b : decoded) d.push_back(b ^ xk);
    auto dp = apply_pivot(d, V1_IDX, true);
    if (dp[8] != 0x01 || dp[11] != 0x02 || dp[2] != dp[14]) return false;
    return common_convert_to_enc_v1(dp, enc_cmd, conf);
}

std::vector<uint8_t> ZhijiaEncoderRemote::convert_from_enc(const BleAdvEncCmd& enc_cmd,
                                                             const BleAdvConfig& conf) {
    auto oarray = common_convert_from_enc_v1(enc_cmd, conf);
    oarray[1] ^= 0x04;
    oarray[8]   = 0x01;
    oarray[11]  = 0x02;
    oarray[14]  = oarray[2];
    oarray[16]  = 0x06;
    // Pivot value from Python reference (noted as uncertain)
    constexpr uint8_t kPivot = 0xC9;
    for (uint8_t& b : oarray) b ^= static_cast<uint8_t>(kPivot ^ 0x06);
    return oarray;
}

// ─── Factory ──────────────────────────────────────────────────────────────────

std::vector<Codec*> get_zhijia_codecs() {
    static ZhijiaEncoderV0     zhijia_v0, zhiguang_v0;
    static ZhijiaEncoderV1     zhijia_v1, zhiguang_v1;
    static ZhijiaEncoderV2     zhijia_v2, zhijia_v2_fl, zhiguang_v2;
    static ZhijiaEncoderRemote zhijia_vr1;
    static bool init = false;
    if (!init) {
        zhijia_v0.header({0xF9, 0x08, 0x49}).prefix({0x08, 0x80, 0x98}).ble(0x1A, 0xFF);
        zhiguang_v0.header({0xF9, 0x08, 0x49}).prefix({0x33, 0xAA, 0x55}).ble(0x1A, 0xFF);

        zhijia_v1.header({0xF9, 0x08, 0x49}).prefix({0x55, 0x08, 0x80, 0x98}).ble(0x1A, 0xFF);
        zhiguang_v1.header({0xF9, 0x08, 0x49}).prefix({0xA0, 0xC0, 0x04, 0x04}).ble(0x1A, 0xFF);

        zhijia_v2.header({0x22, 0x9D}).ble(0x1A, 0xFF);
        zhijia_v2_fl.header({0x22, 0x9D}).ble(0x1A, 0xFF);
        zhiguang_v2.header({0x22, 0x9D}).ble(0x1A, 0xFF);

        zhijia_vr1.header({0xF0, 0xFF}).ble(0x1A, 0xFF);
        init = true;
    }
    return {&zhijia_v0, &zhiguang_v0,
            &zhijia_v1, &zhiguang_v1,
            &zhijia_v2, &zhijia_v2_fl, &zhiguang_v2,
            &zhijia_vr1};
}

} // namespace fanesp::codecs
