#include "le.h"

namespace fanesp::codecs {

const uint8_t LeEncoder::XBOXES[16] = {
    0xCB, 0x6A, 0x95, 0x8D, 0xB6, 0x7B, 0x35, 0x5A,
    0x6E, 0x49, 0x5C, 0x85, 0x37, 0x3C, 0xA6, 0x88
};

uint8_t LeEncoder::_checksum(const std::vector<uint8_t>& buf) const {
    uint32_t sum = 0;
    for (uint8_t b : buf) sum += b;
    return static_cast<uint8_t>(((sum + 1) & 0xFF) ^ 0xFF);
}

std::vector<uint8_t> LeEncoder::_xor_encode(const std::vector<uint8_t>& buf, uint8_t salt) const {
    uint8_t xora = XBOXES[salt & 0x0Fu];
    std::vector<uint8_t> out;
    out.reserve(buf.size());
    for (uint8_t b : buf) out.push_back(b ^ xora);
    return out;
}

std::optional<std::vector<uint8_t>> LeEncoder::decrypt(const std::vector<uint8_t>& buffer) {
    if (buffer.size() < 2) return std::nullopt;
    uint8_t data_len = buffer[0];
    if (buffer[1] != 0x01) return std::nullopt;
    if (static_cast<int>(buffer.size()) < data_len + 1) return std::nullopt;

    int zero_len = static_cast<int>(buffer.size()) - data_len - 1;
    if (zero_len < 0) return std::nullopt;
    for (int i = 0; i < zero_len; i++) {
        if (buffer[buffer.size() - 1 - i] != 0x00) return std::nullopt;
    }

    // Reconstruct: buffer[2:6] + XOR(buffer[6:data_len+1], salt=buffer[2])
    if (data_len < 6) return std::nullopt;
    std::vector<uint8_t> plain(buffer.begin() + 2, buffer.begin() + 6);
    auto tail_enc = std::vector<uint8_t>(buffer.begin() + 6, buffer.begin() + data_len + 1);
    auto tail_dec = _xor_encode(tail_enc, buffer[2]);
    plain.insert(plain.end(), tail_dec.begin(), tail_dec.end());

    if (plain.size() < 2) return std::nullopt;
    if (plain[2] != 0xFE) return std::nullopt;  // decoded_base[4] in full buffer = plain[2]
    uint8_t expected = _checksum(std::vector<uint8_t>(plain.begin(), plain.end() - 1));
    if (expected != plain.back()) return std::nullopt;

    // Return without the checksum byte
    return std::vector<uint8_t>(plain.begin(), plain.end() - 1);
}

std::vector<uint8_t> LeEncoder::encrypt(const std::vector<uint8_t>& decoded) {
    // decoded = convert_from_enc output (no prefix for lelight)
    uint8_t cs = _checksum(decoded);
    std::vector<uint8_t> data;
    data.push_back(static_cast<uint8_t>(decoded.size() + 2));
    data.push_back(0x01);
    data.insert(data.end(), decoded.begin(), decoded.end());
    data.push_back(cs);

    // XOR encode data[6:] using salt = data[2]
    if (data.size() > 6) {
        auto enc_tail = _xor_encode(std::vector<uint8_t>(data.begin() + 6, data.end()), data[2]);
        data.erase(data.begin() + 6, data.end());
        data.insert(data.end(), enc_tail.begin(), enc_tail.end());
    }

    // Pad with zeros to _len bytes
    while (static_cast<int>(data.size()) < _len) data.push_back(0x00);
    return data;
}

bool LeEncoder::convert_to_enc(const std::vector<uint8_t>& decoded,
                                BleAdvEncCmd& enc_cmd, BleAdvConfig& conf) {
    // decoded = uid(4) + 0xFE + index + tx_count + cmd + param + args...
    if (decoded.size() < 9) return false;
    conf.id       = static_cast<uint32_t>(decoded[0])
                  | (static_cast<uint32_t>(decoded[1]) << 8)
                  | (static_cast<uint32_t>(decoded[2]) << 16)
                  | (static_cast<uint32_t>(decoded[3]) << 24);
    conf.index    = decoded[5];
    conf.tx_count = decoded[6];
    enc_cmd.cmd   = decoded[7];
    enc_cmd.param = decoded[8];
    enc_cmd.arg0  = (enc_cmd.param >= 1 && decoded.size() > 9)  ? decoded[9]  : 0;
    enc_cmd.arg1  = (enc_cmd.param >= 2 && decoded.size() > 10) ? decoded[10] : 0;
    enc_cmd.arg2  = (enc_cmd.param >= 3 && decoded.size() > 11) ? decoded[11] : 0;
    return true;
}

std::vector<uint8_t> LeEncoder::convert_from_enc(const BleAdvEncCmd& enc_cmd,
                                                   const BleAdvConfig& conf) {
    std::vector<uint8_t> out = {
        static_cast<uint8_t>(conf.id & 0xFF),
        static_cast<uint8_t>((conf.id >> 8) & 0xFF),
        static_cast<uint8_t>((conf.id >> 16) & 0xFF),
        static_cast<uint8_t>((conf.id >> 24) & 0xFF),
        0xFE,
        conf.index,
        conf.tx_count,
        enc_cmd.cmd,
        enc_cmd.param,
    };
    uint8_t nargs = enc_cmd.param < 3 ? enc_cmd.param : 3;
    const uint8_t args[3] = {enc_cmd.arg0, enc_cmd.arg1, enc_cmd.arg2};
    for (uint8_t i = 0; i < nargs; i++) out.push_back(args[i]);
    return out;
}

std::vector<Codec*> get_le_codecs() {
    static LeEncoder codec_lelight;
    static bool init = false;
    if (!init) {
        codec_lelight.header({0xFF, 0xFF, 0xFF, 0xFF}).ble(0x1A, 0xFF);
        init = true;
    }
    return {&codec_lelight};
}

} // namespace fanesp::codecs
