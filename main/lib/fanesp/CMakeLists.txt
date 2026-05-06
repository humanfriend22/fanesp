idf_component_register(
    SRCS
        "src/ble_adv_codec.cpp"
        "src/ble_adv_utils.cpp"
        "src/fanlamp.cpp"
        "src/remote.cpp"
        "src/smartelfin.cpp"
        "src/ruixin.cpp"
        "src/le.cpp"
        "src/agarce.cpp"
        "src/rw.cpp"
        "src/mantra.cpp"
        "src/zhimei.cpp"
        "src/zhijia.cpp"
        "src/codecs.cpp"
    INCLUDE_DIRS "include"
    REQUIRES mbedtls esp_system bt)
