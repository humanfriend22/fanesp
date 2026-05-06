#include "ble_adv_utils.h"

namespace fanesp {

std::vector<uint8_t> whiten(const std::vector<uint8_t>& buf, uint8_t seed) {
    std::vector<uint8_t> out;
    out.reserve(buf.size());
    uint8_t r = seed;
    for (uint8_t val : buf) {
        uint8_t b = 0;
        for (int j = 0; j < 8; j++) {
            r <<= 1;
            if (r & 0x80) {
                r ^= 0x11;
                b |= static_cast<uint8_t>(1 << j);
            }
            r &= 0x7F;
        }
        out.push_back(val ^ b);
    }
    return out;
}

uint8_t reverse_byte(uint8_t x) {
    x = static_cast<uint8_t>(((x & 0x55u) << 1) | ((x & 0xAAu) >> 1));
    x = static_cast<uint8_t>(((x & 0x33u) << 2) | ((x & 0xCCu) >> 2));
    return static_cast<uint8_t>(((x & 0x0Fu) << 4) | ((x & 0xF0u) >> 4));
}

std::vector<uint8_t> reverse_all(const std::vector<uint8_t>& buf) {
    std::vector<uint8_t> out;
    out.reserve(buf.size());
    for (uint8_t b : buf) {
        out.push_back(reverse_byte(b));
    }
    return out;
}

uint16_t crc16_le(const std::vector<uint8_t>& buf, uint16_t seed, uint16_t poly) {
    uint16_t crc = seed ^ 0xFFFFu;
    for (uint8_t byte : buf) {
        crc ^= byte;
        for (int i = 0; i < 8; i++) {
            if (crc & 0x0001u) {
                crc = static_cast<uint16_t>((crc >> 1) ^ poly);
            } else {
                crc >>= 1;
            }
        }
    }
    return crc ^ 0xFFFFu;
}

uint16_t crc16_ccitt(const std::vector<uint8_t>& buf, uint16_t seed) {
    uint16_t crc = seed;
    for (uint8_t byte : buf) {
        crc ^= static_cast<uint16_t>(byte) << 8;
        for (int i = 0; i < 8; i++) {
            if (crc & 0x8000u) {
                crc = static_cast<uint16_t>((crc << 1) ^ 0x1021u);
            } else {
                crc = static_cast<uint16_t>(crc << 1);
            }
        }
    }
    return crc;
}

std::vector<uint8_t> whiten16(const std::vector<uint8_t>& buf, uint16_t seed,
                               uint16_t param, uint8_t xorer) {
    std::vector<uint8_t> out;
    out.reserve(buf.size());
    uint16_t r = seed;
    for (uint8_t val : buf) {
        uint8_t b = 0;
        for (int j = 0; j < 8; j++) {
            uint16_t high = r & 0x8000u;
            r = static_cast<uint16_t>((r << 1) & 0xFFFFu);
            if (high) {
                r ^= param;
                b |= static_cast<uint8_t>(1u << (7 - j));
            }
            if (r == 0) r = 1061;
        }
        out.push_back(val ^ xorer ^ b);
    }
    return out;
}

static const uint8_t ZHIMEI_MATRIX[16] = {29, 4, 17, 32, 152, 117, 40, 70,
                                           11, 175, 67, 172, 214, 190, 137, 142};

std::vector<uint8_t> zhimei_apply_matrix(std::vector<uint8_t> buf, uint8_t key) {
    uint8_t pivot = ZHIMEI_MATRIX[((buf[1] >> 4) & 15) ^ (buf[1] & 15)];
    for (size_t i = 0; i < buf.size(); i++) {
        buf[i] = static_cast<uint8_t>(((buf[i] ^ pivot) + ZHIMEI_MATRIX[(key + i) & 0xFu] + 256u) % 256u);
    }
    return buf;
}

std::vector<uint8_t> zhimei_unapply_matrix(std::vector<uint8_t> buf, uint8_t key) {
    uint8_t pivot = static_cast<uint8_t>(((buf[0] - ZHIMEI_MATRIX[key & 0xFu] + 256u) % 256u) ^ 0xFFu);
    for (size_t i = 0; i < buf.size(); i++) {
        buf[i] = static_cast<uint8_t>(((buf[i] - ZHIMEI_MATRIX[(key + i) & 0xFu] + 256u) % 256u) ^ pivot);
    }
    return buf;
}

} // namespace fanesp
