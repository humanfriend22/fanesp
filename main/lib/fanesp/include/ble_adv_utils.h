#pragma once

#include <cstdint>
#include <vector>

namespace fanesp {

/**
 * @brief Apply 7-bit LFSR whitening to a buffer (symmetric: decrypt == encrypt).
 *
 * For each byte the LFSR advances 8 steps:
 *   r <<= 1; if (r & 0x80) { r ^= 0x11; b |= bit; } r &= 0x7F;
 * The output byte is input XOR the accumulated LFSR byte.
 *
 * @param buf   Input buffer.
 * @param seed  Initial LFSR state.
 * @return      Whitened buffer of the same length.
 */
std::vector<uint8_t> whiten(const std::vector<uint8_t>& buf, uint8_t seed);

/**
 * @brief Bit-reverse a single byte (e.g. 0xCA → 0x53).
 * @details Three-stage swap: bits 1↔0, 3↔2, 7↔4.
 */
uint8_t reverse_byte(uint8_t x);

/**
 * @brief Apply reverse_byte to every byte in the buffer.
 */
std::vector<uint8_t> reverse_all(const std::vector<uint8_t>& buf);

/**
 * @brief CRC16 ISO14443-A/B (poly=0x8408, reflected input and output).
 *
 * Equivalent to Python's crc16_le(buf, seed, poly=0x8408, ref_in=True, ref_out=True).
 *
 * @param buf   Data to checksum.
 * @param seed  Initial CRC value (XORed with 0xFFFF internally for reflection).
 * @param poly  Reflected polynomial (default 0x8408).
 * @return      16-bit CRC result.
 */
uint16_t crc16_le(const std::vector<uint8_t>& buf, uint16_t seed, uint16_t poly = 0x8408);

/**
 * @brief CRC16-CCITT (poly=0x1021, big-endian, non-reflected).
 *
 * Matches Python's binascii.crc_hqx(data, seed).
 *
 * @param buf   Data to checksum.
 * @param seed  Initial CRC value.
 * @return      16-bit CRC result.
 */
uint16_t crc16_ccitt(const std::vector<uint8_t>& buf, uint16_t seed);

} // namespace ble_adv
