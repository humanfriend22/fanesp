#include "codecs.h"
#include "fanlamp.h"
#include "remote.h"
#include "smartelfin.h"
#include "ruixin.h"
#include "le.h"
#include "agarce.h"
#include "rw.h"
#include "mantra.h"
#include "zhimei.h"
#include "zhijia.h"

namespace fanesp::codecs {

std::vector<Codec*> get_all_codecs() {
    static std::vector<Codec*> all;
    static bool init = false;
    if (!init) {
        auto append = [](std::vector<Codec*>& dst, std::vector<Codec*> src) {
            dst.insert(dst.end(), src.begin(), src.end());
        };
        append(all, get_fanlamp_codecs());
        append(all, get_remote_codecs());
        append(all, get_smartelfin_codecs());
        append(all, get_ruixin_codecs());
        append(all, get_le_codecs());
        append(all, get_agarce_codecs());
        append(all, get_rw_codecs());
        append(all, get_mantra_codecs());
        append(all, get_zhimei_codecs());
        append(all, get_zhijia_codecs());
        init = true;
    }
    return all;
}

} // namespace fanesp::codecs
