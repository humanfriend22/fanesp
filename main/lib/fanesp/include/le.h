#pragma once

#include "ble_adv_codec.h"
#include <vector>

namespace fanesp::codecs {

/**
 * LE Light encoder. 21-byte packet with XOR+SBOX encoding and checksum.
 * The first 4 bytes are the device ID and also provide the XOR salt.
 */
class LeEncoder : public Codec {
public:
    LeEncoder() { _len = 21; }

    std::optional<std::vector<uint8_t>> decrypt(const std::vector<uint8_t>& buffer) override;
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& decoded) override;
    bool convert_to_enc(const std::vector<uint8_t>& decoded,
                        BleAdvEncCmd& enc_cmd, BleAdvConfig& conf) override;
    std::vector<uint8_t> convert_from_enc(const BleAdvEncCmd& enc_cmd,
                                           const BleAdvConfig& conf) override;
    uint8_t get_codec_id() const override { return 0x09; }

private:
    static const uint8_t XBOXES[16];
    std::vector<uint8_t> _xor_encode(const std::vector<uint8_t>& buf, uint8_t salt) const;
    uint8_t _checksum(const std::vector<uint8_t>& buf) const;
};

std::vector<Codec*> get_le_codecs();

} // namespace fanesp::codecs
