idf_component_register(
    SRCS
        "main.cpp"
        "src/device_controller.cpp"
        "src/api.cpp"
    INCLUDE_DIRS "." "include"
    REQUIRES fanesp mbedtls esp_system bt nvs_flash esp_http_server esp_wifi esp_netif esp_event lwip)
