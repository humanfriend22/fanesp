#pragma once

#include "ble_adv_codec.h"
#include <vector>

namespace fanesp::codecs {

std::vector<Codec*> get_all_codecs();

} // namespace fanesp::codecs
