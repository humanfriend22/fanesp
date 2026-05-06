#include "agarce.h"

namespace fanesp::codecs {

const uint8_t AgarceEncoder::MATRIX[8] = {0xAA, 0xBB, 0xCC, 0xDD, 0x5A, 0xA5, 0xA5, 0x5A};

// Symmetric XOR cipher: pattern repeats [pivot0, pivot1, pivot1, pivot0] per 4 bytes.
std::vector<uint8_t> AgarceEncoder::_crypt(const std::vector<uint8_t>& buf, uint16_t seed) const {
    uint8_t pivot0 = seed & 0xFF;
    uint8_t pivot1 = (seed >> 8) & 0xFF;
    std::vector<uint8_t> out;
    out.reserve(buf.size());
    for (size_t i = 0; i < buf.size(); i++) {
        // Python: (i+1)/2 % 2 < 1  →  ((i+1)/2) % 2 == 0  →  i%4 ∈ {0,3}
        int phase = static_cast<int>((i + 1) / 2) % 2;
        uint8_t pivot = (phase == 0) ? pivot0 : pivot1;
        out.push_back(buf[i] ^ MATRIX[i % 8] ^ pivot);
    }
    return out;
}

std::optional<std::vector<uint8_t>> AgarceEncoder::decrypt(const std::vector<uint8_t>& buffer) {
    if (buffer.size() < 2) return std::nullopt;
    // Outer checksum: sum(buffer[:-1]) & 0xFF == buffer[-1]
    uint8_t outer_sum = 0;
    for (size_t i = 0; i + 1 < buffer.size(); i++) outer_sum += buffer[i];
    if (outer_sum != buffer.back()) return std::nullopt;

    uint16_t seed = static_cast<uint16_t>(buffer[1]) | (static_cast<uint16_t>(buffer[2]) << 8);
    // Decrypt inner bytes: buffer[3:-1]
    auto inner_enc = std::vector<uint8_t>(buffer.begin() + 3, buffer.end() - 1);
    auto inner = _crypt(inner_enc, seed);

    // Inner checksum: sum(inner[:-1]) & 0xFF == inner[-1]
    if (inner.empty()) return std::nullopt;
    uint8_t inner_sum = 0;
    for (size_t i = 0; i + 1 < inner.size(); i++) inner_sum += inner[i];
    if (inner_sum != inner.back()) return std::nullopt;

    // Exclude pairing group commands
    bool is_pair = (inner[8] & 0xF0) == 0x00;
    if (is_pair && inner[12] == 0x00) return std::nullopt;

    // Reconstruct readable buffer: [prefix, seed_lo, seed_hi, ...inner_without_checksum...]
    uint8_t prefix = buffer[0];
    std::vector<uint8_t> out;
    out.push_back(prefix);
    out.push_back(buffer[1]);
    out.push_back(buffer[2]);

    // Inner data (strip checksum byte)
    std::vector<uint8_t> inner_data(inner.begin(), inner.end() - 1);

    if (is_pair) {
        prefix |= (inner_data[10] & 0x0Fu) << 4;
        inner_data[12] = static_cast<uint8_t>(((inner_data[12] & 0x0Fu) << 4) + inner_data[11]);
        inner_data[11] = 0;
        inner_data[10] = 0;
        out[0] = prefix;
    } else {
        inner_data[12] = static_cast<uint8_t>(((inner_data[12] & 0x0Fu) << 4) + (inner_data[8] & 0x0Fu));
    }

    out.insert(out.end(), inner_data.begin(), inner_data.end());
    return out;
}

std::vector<uint8_t> AgarceEncoder::encrypt(const std::vector<uint8_t>& buffer) {
    // buffer = [prefix, seed_lo, seed_hi, ...data...]
    if (buffer.size() < 3) return {};
    uint16_t seed = static_cast<uint16_t>(buffer[1]) | (static_cast<uint16_t>(buffer[2]) << 8);

    std::vector<uint8_t> decoded(buffer.begin() + 3, buffer.end());
    bool is_pair = (decoded[8] == 0x00);
    uint8_t prefix = buffer[0];

    if (is_pair) {
        decoded[10] = (prefix & 0xF0u) >> 4;
        decoded[11] = decoded[12] & 0x0Fu;
        decoded[12] = static_cast<uint8_t>(((decoded[12] >> 4) & 0x0Fu) + 0xC0u);
        prefix = prefix & 0x0Fu;
    } else {
        decoded[8] |= decoded[12] & 0x0Fu;
        decoded[12] = (decoded[12] >> 4) & 0x0Fu;
    }

    // Append inner checksum
    uint8_t inner_sum = 0;
    for (uint8_t b : decoded) inner_sum += b;
    decoded.push_back(inner_sum);

    // Encrypt inner bytes
    auto encrypted = _crypt(decoded, seed);

    // Build outer packet: [prefix, seed_lo, seed_hi, ...encrypted..., outer_checksum]
    std::vector<uint8_t> out;
    out.push_back(prefix);
    out.push_back(buffer[1]);
    out.push_back(buffer[2]);
    out.insert(out.end(), encrypted.begin(), encrypted.end());

    uint8_t outer_sum = 0;
    for (uint8_t b : out) outer_sum += b;
    out.push_back(outer_sum);
    return out;
}

bool AgarceEncoder::convert_to_enc(const std::vector<uint8_t>& decoded,
                                    BleAdvEncCmd& enc_cmd, BleAdvConfig& conf) {
    // After prefix strip: [seed_lo(0), seed_hi(1), tx_count(2), arc(3), 0x00(4), 0x10(5),
    //                       id(6-9), cmd(10), arg0(11), arg1(12), arg2(13), index(14)]
    if (decoded.size() < 15) return false;
    conf.seed              = static_cast<uint16_t>(decoded[0]) | (static_cast<uint16_t>(decoded[1]) << 8);
    conf.tx_count          = decoded[2];
    conf.app_restart_count = decoded[3];
    conf.id                = static_cast<uint32_t>(decoded[6])
                           | (static_cast<uint32_t>(decoded[7]) << 8)
                           | (static_cast<uint32_t>(decoded[8]) << 16)
                           | (static_cast<uint32_t>(decoded[9]) << 24);
    enc_cmd.cmd            = decoded[10] & 0xF0u;
    enc_cmd.arg0           = decoded[11];
    enc_cmd.arg1           = decoded[12];
    enc_cmd.arg2           = decoded[13];
    conf.index             = decoded[14];
    return true;
}

std::vector<uint8_t> AgarceEncoder::convert_from_enc(const BleAdvEncCmd& enc_cmd,
                                                       const BleAdvConfig& conf) {
    return {
        static_cast<uint8_t>(conf.seed & 0xFF),
        static_cast<uint8_t>((conf.seed >> 8) & 0xFF),
        conf.tx_count,
        conf.app_restart_count,
        0x00,
        0x10,
        static_cast<uint8_t>(conf.id & 0xFF),
        static_cast<uint8_t>((conf.id >> 8) & 0xFF),
        static_cast<uint8_t>((conf.id >> 16) & 0xFF),
        static_cast<uint8_t>((conf.id >> 24) & 0xFF),
        enc_cmd.cmd,
        enc_cmd.arg0,
        enc_cmd.arg1,
        enc_cmd.arg2,
        conf.index,
    };
}

std::vector<Codec*> get_agarce_codecs() {
    static AgarceEncoder codec_v3, codec_v4;
    static bool init = false;
    if (!init) {
        codec_v3.header({0xF9, 0x09}).prefix({0x83}).ble(0x19, 0xFF);
        codec_v4.header({0xF9, 0x09}).prefix({0x84}).ble(0x19, 0xFF);
        init = true;
    }
    return {&codec_v3, &codec_v4};
}

} // namespace fanesp::codecs
