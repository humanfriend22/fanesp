idf_component_register(
    SRCS
        "src/ble_adv_codec.cpp"
        "src/ble_adv_utils.cpp"
        "src/fanlamp.cpp"
    INCLUDE_DIRS "include"
    REQUIRES mbedtls esp_system bt)
