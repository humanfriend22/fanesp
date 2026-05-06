#pragma once

#include "ble_adv_codec.h"
#include <vector>

namespace fanesp::codecs {

/**
 * Agarce (Smart Light) encoder. 18-byte packet with XOR matrix + dual checksum.
 * The prefix byte distinguishes v3 (0x83) from v4 (0x84).
 */
class AgarceEncoder : public Codec {
public:
    AgarceEncoder() { _len = 18; _seed_max = 0xFFF5; }

    std::optional<std::vector<uint8_t>> decrypt(const std::vector<uint8_t>& buffer) override;
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& decoded) override;
    bool convert_to_enc(const std::vector<uint8_t>& decoded,
                        BleAdvEncCmd& enc_cmd, BleAdvConfig& conf) override;
    std::vector<uint8_t> convert_from_enc(const BleAdvEncCmd& enc_cmd,
                                           const BleAdvConfig& conf) override;
    uint8_t get_codec_id() const override { return 0x0A; }

private:
    static const uint8_t MATRIX[8];
    std::vector<uint8_t> _crypt(const std::vector<uint8_t>& buf, uint16_t seed) const;
};

std::vector<Codec*> get_agarce_codecs();

} // namespace fanesp::codecs
