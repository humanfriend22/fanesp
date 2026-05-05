#pragma once

#include "device_controller.h"
#include <esp_http_server.h>

class API {
public:
    API(DeviceController *controller);
    ~API();

    esp_err_t start();
    void stop();

private:
    DeviceController *_controller;
    httpd_handle_t _server;

    static esp_err_t _root_handler(httpd_req_t *req);
    static esp_err_t _get_device_list_handler(httpd_req_t *req);
    static esp_err_t _device_handler(httpd_req_t *req);
    static esp_err_t _discover_handler(httpd_req_t *req);
    static esp_err_t _get_device_features_handler(httpd_req_t *req);
    static esp_err_t _execute_feature_handler(httpd_req_t *req);
};
