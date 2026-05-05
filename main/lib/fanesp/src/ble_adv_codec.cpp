#include "ble_adv_codec.h"

#include <esp_random.h>

namespace fanesp {

// ─── BleAdvAdvertisement ────────────────────────────────────────────────────

static constexpr uint8_t RECOGNISED_TYPES[] = {0x03, 0x05, 0x07, 0x16, 0xFF};

static bool is_recognised_type(uint8_t t) {
    for (uint8_t rt : RECOGNISED_TYPES) {
        if (t == rt) return true;
    }
    return false;
}

BleAdvAdvertisement BleAdvAdvertisement::from_raw(const std::vector<uint8_t>& raw_adv) {
    BleAdvAdvertisement adv;
    bool primary_found = false;

    const uint8_t* p   = raw_adv.data();
    size_t         rem = raw_adv.size();

    while (rem > 2) {
        uint8_t part_len  = p[0];
        uint8_t part_type = p[1];

        if (part_len > rem) break;

        if (is_recognised_type(part_type)) {
            std::vector<uint8_t> payload(p + 2, p + part_len + 1);
            if (!primary_found) {
                adv.ble_type   = part_type;
                adv.raw        = std::move(payload);
                primary_found  = true;
            } else {
                adv.second_type = part_type;
                adv.second_raw  = std::move(payload);
                break;
            }
        }

        p   += part_len + 1;
        rem -= part_len + 1;
    }

    if (!primary_found) {
        // No recognised type: treat entire buffer as raw with type 0.
        adv.ble_type = 0x00;
        adv.raw      = raw_adv;
    }

    return adv;
}

std::vector<uint8_t> BleAdvAdvertisement::to_raw() const {
    std::vector<uint8_t> out;

    if (ad_flag != 0) {
        out.push_back(0x02);
        out.push_back(0x01);
        out.push_back(ad_flag);
    }

    if (ble_type != 0) {
        out.push_back(static_cast<uint8_t>(raw.size() + 1));
        out.push_back(ble_type);
        out.insert(out.end(), raw.begin(), raw.end());
    } else {
        out.insert(out.end(), raw.begin(), raw.end());
    }

    if (second_raw.has_value()) {
        const auto& sr = second_raw.value();
        out.push_back(static_cast<uint8_t>(sr.size() + 1));
        out.push_back(second_type);
        out.insert(out.end(), sr.begin(), sr.end());
    }

    return out;
}

// ─── Codec ────────────────────────────────────────────────────────────

Codec& Codec::ble(uint8_t ad_flag, uint8_t ble_type) {
    _ad_flag  = ad_flag;
    _ble_type = ble_type;
    return *this;
}

Codec& Codec::header(std::vector<uint8_t> hdr, int start_pos) {
    _header           = std::move(hdr);
    _header_start_pos = start_pos;
    return *this;
}

Codec& Codec::prefix(std::vector<uint8_t> pfx) {
    _prefix = std::move(pfx);
    return *this;
}

Codec& Codec::footer(std::vector<uint8_t> ftr) {
    _footer = std::move(ftr);
    return *this;
}

bool Codec::decode_adv(const BleAdvAdvertisement& adv,
                               BleAdvEncCmd& enc_cmd, BleAdvConfig& conf) {
    // 1. BLE type check.
    if (adv.ble_type != _ble_type) return false;

    // 2. Length check: payload must be _len bytes after removing header and footer.
    int last_pos = static_cast<int>(adv.raw.size()) - static_cast<int>(_footer.size());
    int data_len = last_pos - _header_start_pos - static_cast<int>(_header.size());
    if (data_len != _len) return false;

    // 3. Header check.
    if (static_cast<int>(adv.raw.size()) < _header_start_pos + static_cast<int>(_header.size()))
        return false;
    for (size_t i = 0; i < _header.size(); i++) {
        if (adv.raw[_header_start_pos + i] != _header[i]) return false;
    }

    // 4. Footer check.
    if (last_pos < 0 || static_cast<size_t>(last_pos) + _footer.size() > adv.raw.size())
        return false;
    for (size_t i = 0; i < _footer.size(); i++) {
        if (adv.raw[last_pos + i] != _footer[i]) return false;
    }

    // Build buffer: raw[0 .. header_start_pos) ++ raw[header_end .. last_pos).
    std::vector<uint8_t> buf(adv.raw.begin(), adv.raw.begin() + _header_start_pos);
    buf.insert(buf.end(),
               adv.raw.begin() + _header_start_pos + static_cast<int>(_header.size()),
               adv.raw.begin() + last_pos);

    // 5. Decrypt.
    auto decrypted = decrypt(buf);
    if (!decrypted.has_value()) return false;
    const auto& dec = decrypted.value();

    // 6. Prefix check.
    if (dec.size() < _prefix.size()) return false;
    for (size_t i = 0; i < _prefix.size(); i++) {
        if (dec[i] != _prefix[i]) return false;
    }

    // 7. Strip prefix and convert.
    std::vector<uint8_t> payload(dec.begin() + _prefix.size(), dec.end());
    return convert_to_enc(payload, enc_cmd, conf);
}

std::vector<BleAdvAdvertisement> Codec::encode_advs(const BleAdvEncCmd& enc_cmd,
                                                            BleAdvConfig& conf) {
    // 1. Increment rolling counter.
    conf.tx_count = static_cast<uint8_t>((conf.tx_count + _tx_step) % _tx_max);
    if (conf.tx_count == 0) {
        conf.app_restart_count = static_cast<uint8_t>((conf.app_restart_count + 1) % 255);
    }

    // 2. Generate seed on first use.
    if (conf.seed == 0 && _seed_max > 0) {
        conf.seed = static_cast<uint16_t>(1 + esp_random() % static_cast<uint32_t>(_seed_max));
    }

    // 3. Serialise command.
    auto payload = convert_from_enc(enc_cmd, conf);

    // 4. Prepend prefix and encrypt.
    std::vector<uint8_t> plain(_prefix.begin(), _prefix.end());
    plain.insert(plain.end(), payload.begin(), payload.end());
    auto encrypted = encrypt(plain);

    // 5. Reinsert header and append footer.
    std::vector<uint8_t> full;
    full.insert(full.end(), encrypted.begin(), encrypted.begin() + _header_start_pos);
    full.insert(full.end(), _header.begin(), _header.end());
    full.insert(full.end(), encrypted.begin() + _header_start_pos, encrypted.end());
    full.insert(full.end(), _footer.begin(), _footer.end());

    BleAdvAdvertisement adv;
    adv.ble_type    = _ble_type;
    adv.raw         = std::move(full);
    adv.ad_flag     = _ad_flag;
    adv.second_type = second_type;
    adv.second_raw  = second_raw;

    return {adv};
}

} // namespace ble_adv
