#pragma once

#include "ble_adv_codec.h"
#include <vector>

namespace fanesp::codecs {

/**
 * Smart Elfin encoder. 12-byte packet with 4 fixed bytes inserted at offset 4.
 * Uses secondary AD record (type 0x16, 8 zero bytes).
 */
class SmartElfinEncoder : public Codec {
public:
    SmartElfinEncoder() {
        _len     = 12;
        _tx_max  = 0xFE;
        _tx_step = 2;
        second_type = 0x16;
        second_raw  = std::vector<uint8_t>(8, 0x00);
    }

    std::optional<std::vector<uint8_t>> decrypt(const std::vector<uint8_t>& buffer) override;
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& decoded) override;
    bool convert_to_enc(const std::vector<uint8_t>& decoded,
                        BleAdvEncCmd& enc_cmd, BleAdvConfig& conf) override;
    std::vector<uint8_t> convert_from_enc(const BleAdvEncCmd& enc_cmd,
                                           const BleAdvConfig& conf) override;
    uint8_t get_codec_id() const override { return 0x07; }

private:
    static constexpr uint8_t FIXED[4] = {0x64, 0xE5, 0xE3, 0xBA};
};

std::vector<Codec*> get_smartelfin_codecs();

} // namespace fanesp::codecs
