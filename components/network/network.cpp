#include "network.h"

/* Singleton instance of the Network class. */
Network *Network::_instance{nullptr};

/* A singleton class that handles device-related tasks. */
Device *Network::_device{nullptr};

/* A class that handles sensor-related tasks. */
Sensor *Network::_sensor{nullptr};

/* A class that handles led-related tasks.*/
Led *Network::_led{nullptr};

/* Determines whether the device should attempt to reconnect to the Wi-Fi network. */
std::atomic_bool Network::_reconnect{false};

/* Indicates if the API key should be obtained from the server. */
std::atomic_bool Network::_get_key{true};

/* Indicates if the API key is obtained from the server. */
std::atomic_bool Network::_got_key{false};

/* The Device's mac address. */
char Network::_mac[]{};

/* Api key used to validate requests. */
char Network::_api_key[]{};

/* The number of Wi-Fi reconnect attempts. */
uint8_t Network::_retries{0};

/* Handle for an HTTP server instance listening on port 80. */
httpd_handle_t Network::_server{nullptr};

/* The http client's configuration. */
esp_http_client_config_t Network::_client_config{};

/* The handle to the http client. */
esp_http_client_handle_t Network::_client{};

/* Used to keep track of the network's status.*/
net_state_t  Network::_net_state{NOT_INITIALIZED};

/* Used to keep track of the state of the server.*/
server_state_t   Network::_server_state{UNKOWN};

/* A pointer to the start of the smart config key. */
extern const uint8_t sc_key_start[] asm("_binary_sc_key_start");

/* A pointer to the end of the smart config key. */
extern const uint8_t sc_key_end[] asm("_binary_sc_key_end");

/**
 * Get the Network class instance. 
 * @return A pointer to the Network class instance.
 */
Network *Network::instance(void)
{
    if(_instance == nullptr)
    {
        _instance = new Network();
    }

    return _instance;
}

/**
 * Wi-Fi events callback handler that is called when a Wi-Fi event occurs.
 * @param arg Pointer to the user passed to esp_event_loop_create when the event loop was created.
 * @param event_base The event base that the event is associated with.
 * @param event_id The event ID.
 * @param event_data The data associated with the event.
 */
void Network::wifi_evt_handler(void* arg, esp_event_base_t event_base, const int32_t event_id, void* event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) 
    {
        if(_device->configured())
        {
            ESP_LOGI(tag," %s -> Connecting to wifi", __func__);
            _net_state = CONNECTING;
            esp_wifi_connect();
        }
        else
            smart_config();
    } 
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) 
    {
        if(_net_state == INITIALIZED) return;
            
        ESP_LOGI(tag, "%s -> Device disconnected from the router", __func__);
        
        _led->set_mode(SLOW_BLINK);

        _net_state = DISCONNECTED;
        _reconnect = true;
    }
    else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) 
    {
        _net_state = CONNECTED;
        const auto event = static_cast<ip_event_got_ip_t*>(event_data);

        ESP_LOGI(tag, "%s -> WiFi connected. Got assigned IP address: %s", __func__, ip4addr_ntoa(&event->ip_info.ip));

        if(!_led->state()) _led->toggle(true);
            
        _led->set_mode(STATIC);

        _device->set_clock();

        if(_reconnect)
        {
            _retries = 0;
            _reconnect = false;
        }

        configure_client_config();
    }
    else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_LOST_IP) 
    {
        ESP_LOGI(tag, "%s -> Lost IP address", __func__);
        _net_state = WAITING_FOR_IP;
        _led->set_mode(SLOW_BLINK);
    }
}

/**
 * Smart config events callback handler that is called by when a smart config event occurs.
 * @param arg Pointer to the user data passed to esp_event_loop_create when the event loop was created.
 * @param event_base The event base that the event is associated with.
 * @param event_id The event ID.
 * @param event_data The data associated with the event.
 */
void Network::sc_evt_handler(void* arg, const esp_event_base_t event_base, int32_t event_id, void* event_data)
{
    if(event_base == SC_EVENT)
    {
        ESP_LOGI(tag, "%s -> Got event Event ID %d", __func__, event_id);

        const auto event_type = static_cast<smartconfig_event_t>(event_id);

        switch (event_type)
        {
            case SC_EVENT_SCAN_DONE:
                ESP_LOGI(tag, "%s -> Scan done", __func__);
                break;
            case SC_EVENT_FOUND_CHANNEL:
                ESP_LOGI(tag, "%s -> Found channel", __func__);
                break;
            case SC_EVENT_GOT_SSID_PSWD:
            {
                ESP_LOGI(tag, "%s -> Got SSID and password", __func__);

                auto *data = static_cast<smartconfig_event_got_ssid_pswd_t *>(event_data);

                const auto result = on_setup(data);

                if(result == ESP_OK) break;

                ESP_LOGI(tag, "%s -> Smartconfig ack send error: %s", __func__, esp_err_to_name(result));

                sc_send_ack_stop();
                esp_smartconfig_stop();
                smart_config();
                
                break;
            }
            default:
                ESP_LOGI(tag, "%s -> Ack Sent. Successful configured device", __func__);
                esp_smartconfig_stop();
                _device->restart(5000);
                break;
        }
    }
}

/**
 * Sends a http error to the client.
 * @param req The request object.
 * @param status The HTTP status code to return.
 * @return ESP_OK.
 */
esp_err_t Network::on_error(httpd_req_t *req, const char *status)
{
    httpd_resp_set_status(req, status);
    httpd_resp_send(req, nullptr, 0);
    return ESP_OK;
}

/**
 * Checks the request header for authorization headers and a valid api-key.
 * @param req The request object.
 * @return An esp_err_t result of the.
 * @return
 *    - ESP_OK Success.
 *    - ESP_FAIL Request is not authorized.
 */
esp_err_t Network::auth(httpd_req_t *req)
{
    ESP_LOGI(tag, "%s -> Verifying if the request is authorized", __func__);

    const auto *hdr_key = "x-api-key";

    auto result = ESP_FAIL;

    auto hdr_len = httpd_req_get_hdr_value_len(req, hdr_key);

    if (hdr_len < 1) 
    {
        ESP_LOGE(tag, "%s -> Couldn't find the -> %s header", __func__, hdr_key);
        return result;
    }

    hdr_len += 1;

    ESP_LOGI(tag, "%s -> Found -> %s header", __func__, hdr_key);

    auto *api_key = static_cast<char *>(malloc(hdr_len));

    if(!api_key)
    {
        ESP_LOGE(tag, "%s -> Failed to allocate memory for api_key buffer", __func__);
        return result;
    }

    result = httpd_req_get_hdr_value_str(req, hdr_key, api_key, hdr_len);

    if(result != ESP_OK)
    {
        ESP_LOGE(tag, "%s -> Couldn't get -> %s header value", __func__, hdr_key);
        free(api_key);
        return result;
    }

    ESP_LOGI(tag, "%s -> %s Header value retrieved, verifying match", __func__, hdr_key);

    if(!_got_key)
        result = strcmp(x_key, api_key) == 0 ? ESP_OK : ESP_FAIL;
    else
        result = strcmp(_api_key, api_key) == 0 ? ESP_OK : ESP_FAIL;

    ESP_LOGI(tag, "%s -> Request is -> %s", __func__, result == ESP_OK ? "authorized" : "not authorized");

    free(api_key);

    return result;
}

/**
 * Http Get /config endpoint handler. 
 * Creates and sends a JSON document containing the device's configuration to the client.
 * @param req The request object.
 * @return ESP_OK
 */
esp_err_t Network::on_get_config(httpd_req_t *req)
{   
    ESP_LOGI(tag, "%s -> Endpoint reached", __func__);

    if(auth(req) != ESP_OK) return on_error(req, "401");
    
    auto *obj = cJSON_CreateObject();

    const auto *config = _device->config();
            
    cJSON_AddStringToObject(obj, "name", config->name);
    cJSON_AddStringToObject(obj, "sta_ssid", config->sta_ssid);
    cJSON_AddStringToObject(obj, "host", config->host);
    cJSON_AddStringToObject(obj, "uuid", config->uuid);

    auto *body = cJSON_Print(obj);

    httpd_resp_set_type(req, app_json);
    httpd_resp_send(req, body, strlen(body));
        
    cJSON_free(body);
    cJSON_Delete(obj);

    return ESP_OK;
}

/**
 * HTTP POST /config endpoint handler. 
 * Parses the client's JSON object of the device config and writes the new config to the device's storage.
 * @param req The request object.
 * @return ESP_OK
 */
esp_err_t Network::on_post_config(httpd_req_t *req)
{
    ESP_LOGI(tag, "%s -> Endpoint reached", __func__);
    
    if(auth(req) != ESP_OK) return on_error(req, "401");

    const auto *old_config = _device->config();

    device_config_t config{};
    
    char buf[350]{};

    const auto len = req->content_len;

    const auto ret = httpd_req_recv(req, buf, len);

    if(ret <= 0)
        if(ret == HTTPD_SOCK_ERR_TIMEOUT) 
            return on_error(req);

    auto *obj = cJSON_Parse(buf);

    if(obj == nullptr)
        return on_error(req, "400");
    
    if (cJSON_HasObjectItem(obj, "name"))
        strcpy(config.name , cJSON_GetObjectItem(obj, "name")->valuestring);
    else
        strcpy(config.name , old_config->name);

    if (cJSON_HasObjectItem(obj, "sta_ssid"))
        strcpy(config.sta_ssid , cJSON_GetObjectItem(obj, "sta_ssid")->valuestring);
    else
        strcpy(config.sta_ssid , old_config->sta_ssid);

    if (cJSON_HasObjectItem(obj, "sta_pass"))
        strcpy(config.sta_pass , cJSON_GetObjectItem(obj, "sta_pass")->valuestring);
    else
        strcpy(config.sta_pass , old_config->sta_pass);

    if (cJSON_HasObjectItem(obj, "host"))
        strcpy(config.host , cJSON_GetObjectItem(obj, "host")->valuestring);
    else
        strcpy(config.host , old_config->host);

    strcpy(config.uuid, _device->config()->uuid);

    httpd_resp_set_type(req, app_json);

    const auto result = _device->write_config(config);

    if(result != ESP_OK)
    {
        ESP_LOGE(tag, "%s -> Failed to write new config to storage", __func__);
        httpd_resp_set_status(req, "500");
        httpd_resp_send(req, R"({"message": Failed to write new config to storage.})" , _strlen);
        cJSON_Delete(obj);
        return ESP_OK;
    }
    
    httpd_resp_set_status(req, "202");

    httpd_resp_send(req, R"({"message": Successfully updated config, device will restart.})" , _strlen);
    
    cJSON_Delete(obj);

    _device->restart(2000);

    return result;
}

/**
 * HTTP_GET /info endpoint handler.
 * Creates and sends a JSON document containing the device's information to the client.
 * @param req The request object.
 * @return ESP_OK
 */
esp_err_t Network::on_info(httpd_req_t *req)
{  
    ESP_LOGI(tag, "%s -> Endpoint reached", __func__);

    if(auth(req) != ESP_OK) return on_error(req, "401");

    auto *obj = static_cast<char *>(malloc(300));

    const auto result = _device->read_info(obj, _mac);

    if(result ==  ESP_OK)
	{
        httpd_resp_set_type(req, app_json);
        httpd_resp_send(req, obj, strlen(obj));
    }
    else
        httpd_resp_send_500(req);
      
    free(obj);

    return ESP_OK;
}

/**
 * HTTP_GET /sensor endpoint handler
 * Gets the temp and humidity and sends it to the client.
 * @param req The request object.
 * @return ESP_OK
 */
esp_err_t Network::on_sensor(httpd_req_t *req)
{
    ESP_LOGI(tag, "%s -> Endpoint reached", __func__);

    if(auth(req) != ESP_OK) return on_error(req, "401");

    int16_t temp;
    int16_t humidity;

    httpd_resp_set_type(req, app_json);

    const auto result = _sensor->read(&temp, &humidity);

    if(result != ESP_OK)
    {
        ESP_LOGE(tag, "%s -> Failed to get temperature and humidity", __func__);
        httpd_resp_set_status(req, "500");
        httpd_resp_send(req, R"({"message": Failed to get temperature and humidity.})" , _strlen);
        return ESP_OK;
    }

    auto *doc = cJSON_CreateObject();

	cJSON_AddNumberToObject(doc, "temp", temp);
	cJSON_AddNumberToObject(doc, "humidity", humidity);

	auto *body = cJSON_Print(doc);

	httpd_resp_send(req, body, strlen(body));

    cJSON_free(body);
    cJSON_Delete(doc);

    return result;
}

/**
 * HTTP_GET /restart endpoint handler.
 * Schedules the device to restart.
 * @param req The request object.
 * @return ESP_OK
 */
esp_err_t Network::on_restart(httpd_req_t *req)
{
    ESP_LOGI(tag, "%s -> Endpoint reached", __func__);

    constexpr auto result = ESP_OK;

    if(auth(req) != ESP_OK) return on_error(req, "401");

    httpd_resp_send(req, R"({"message": Device will restart shortly.})", _strlen);

    _device->restart(1000);

    return result;
}

/**
 * HTTP_GET /update endpoint handler.
 * Configures the OTA update process.
 * @param req The request object.
 * @return ESP_OK
 */
esp_err_t Network::on_update(httpd_req_t *req)
{
    ESP_LOGI(tag, "%s -> Endpoint reached", __func__);

    constexpr auto result = ESP_OK;

    if(auth(req) != ESP_OK) return on_error(req, "401");

    configure_ota(req);

    return result;
}

/**
 * Configures the sta configuration, writes the new device config to storage and the connects to the Wi-Fi.
 * @param data Struct that contains the SSID and password of the network to connect to and the device config.
 * @return
 *    - ESP_OK Success.
 *    - ESP_FAIL Failed to get or write the right data to storage.
 */
esp_err_t Network::on_setup(smartconfig_event_got_ssid_pswd_t *data)
{
    ESP_LOGI(tag, "%s -> Running smart config setup", __func__);

    uint8_t buf[150]{};

    auto result = esp_smartconfig_get_rvd_data(buf, sizeof(buf));

    if(result != ESP_OK)
    {
        ESP_LOGI(tag, "%s -> Smartconfig get reserved data error: %s", __func__, esp_err_to_name(result));
        return result;
    }
    
    ESP_LOGI(tag, "%s -> Smartconfig reserved data: %s", __func__, buf);
    
    auto *obj = cJSON_Parse(reinterpret_cast<char*>(buf));

    if(obj == nullptr)
    {
        ESP_LOGI(tag, "%s -> Failed to parse json, Invalid data received  : %s", __func__, buf);
        return ESP_FAIL;
    }

    device_config_t config{};

    wifi_config_t wifi_config{};

    memcpy(wifi_config.sta.ssid, data->ssid, std::min(sizeof(wifi_sta_config_t::ssid), sizeof(smartconfig_event_got_ssid_pswd_t::ssid)));
    memcpy(wifi_config.sta.password, data->password, std::min(sizeof(wifi_sta_config_t::password), sizeof(smartconfig_event_got_ssid_pswd_t::password)));
    
    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    wifi_config.sta.pmf_cfg.capable = true;
    wifi_config.sta.pmf_cfg.required = false;

    wifi_config.sta.bssid_set = data->bssid_set;
    
    if (wifi_config.sta.bssid_set == true)
        memcpy(wifi_config.sta.bssid, data->bssid, sizeof(wifi_config.sta.bssid));

    ESP_ERROR_CHECK(esp_wifi_disconnect());
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_FLASH));
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
    ESP_ERROR_CHECK(esp_wifi_connect());

    memcpy(config.sta_ssid, data->ssid, std::min(sizeof(device_config_t::sta_ssid), sizeof(smartconfig_event_got_ssid_pswd_t::ssid)));
    memcpy(config.sta_pass, data->password, std::min(sizeof(device_config_t::sta_pass), sizeof(smartconfig_event_got_ssid_pswd_t::password)));

    strcpy(config.name , cJSON_GetObjectItem(obj, "name")->valuestring);
    strcpy(config.host , cJSON_GetObjectItem(obj, "host")->valuestring);
    strcpy(config.uuid, _device->config()->uuid);

    ESP_LOGI(tag, "%s -> Setup ssid: %s, password: %s", __func__, config.sta_ssid, config.sta_pass);

    cJSON_free(buf);
    cJSON_Delete(obj);

    result = _device->write_config(config);

    if(result != ESP_OK)
        ESP_LOGE(tag,"%s -> Failed to write device config", __func__);

    ESP_LOGI(tag, "%s -> Finished device smart config setup", __func__);

    return result;
}

/**
 * Sets the smart config, registers an event handler for the smart config event and starts the smart config process. 
 */
void Network::smart_config(void)
{
    ESP_LOGI(tag, "%s -> Device not configured", __func__);

    _led->set_mode(FAST_BLINK);

    auto key = (char *)sc_key_start; 

    ESP_ERROR_CHECK(esp_event_handler_register(SC_EVENT, ESP_EVENT_ANY_ID, &sc_evt_handler, nullptr));

    ESP_ERROR_CHECK(esp_smartconfig_set_type(SC_TYPE_ESPTOUCH_V2));

    const smartconfig_start_config_t config = {
        .enable_log = true,
        .esp_touch_v2_enable_crypt = true,
        .esp_touch_v2_key = key
    };

    ESP_ERROR_CHECK(esp_esptouch_set_timeout(150));

    ESP_ERROR_CHECK(esp_smartconfig_start(&config));

    ESP_LOGI(tag, "%s -> Starting smart config with encryption key of -> %s", __func__, key);
}

/**
 * Sets the http client config for the OTA update. When successful, the device is restarted.
 * @param req The request object.
 */
void Network::configure_ota(httpd_req_t *req)
{
    ESP_LOGI(tag, "%s -> Configuring ota", __func__);

    char buf[100]{};

    const auto len = req->content_len;

    ESP_LOGI(tag, "%s -> Http content len -> %d", __func__, len);

    const auto ret = httpd_req_recv(req, buf, len);

    ESP_LOGI(tag, "%s -> Http read size -> %d", __func__, ret);

    if(ret <= 0)
    {
        on_error(req, "500");
        return;
    }

    auto *obj = cJSON_Parse(buf);

    if(obj == nullptr)
    {
        on_error(req, "500");
        return;
    }

    const auto *config = _device->config();

    char path[200] = "/bin/"; 

    strcat(path, cJSON_GetObjectItem(obj, "filename")->valuestring);

    esp_http_client_config_t client_config{};

    client_config.host = config->host;
    client_config.port = 3000;
    client_config.path = path;

    ESP_LOGI(tag, "%s-> Attempting to download update from -> %s", __func__, path);
    
    const auto result = esp_https_ota(&client_config);

    ESP_LOGI(tag, "%s -> Setting response type", __func__);

    httpd_resp_set_type(req, app_json);

    if (result != ESP_OK)
    {
        ESP_LOGE(tag, "%s -> Firmware Upgrades Failed reason -> %s", __func__, esp_err_to_name(result));
        httpd_resp_send(req, R"({"message": Firmware Upgrades Failed})", _strlen);
        return;
    }

    httpd_resp_send(req, R"({"message": Firmware Upgraded Successful, Device will restart})", _strlen);
    
    cJSON_free(obj);

    _device->restart(4000);
}

/**
 * Sends the temperature and humidity from the sensor to the server.
 */
void Network::on_send(void)
{
    ESP_LOGI(tag, "%s -> Sending sensor data to the server", __func__);

    int16_t temp;
    int16_t humidity;

    auto result = _sensor->read(&temp, &humidity);

    if(result != ESP_OK) return;

    auto *doc = cJSON_CreateObject();

	cJSON_AddNumberToObject(doc, "temp", temp);
	cJSON_AddNumberToObject(doc, "humidity", humidity);

	auto *body = cJSON_Print(doc);

    ESP_LOGI(tag, "Sending contents to server");

    result = send_req("/api/climate", body, HTTP_METHOD_POST);
    
    if(result == ESP_OK) 
    {
        auto status = esp_http_client_get_status_code(_client);

        ESP_LOGI(tag, "%s -> HTTPS Status = %d, content_length = %d", __func__, status, esp_http_client_get_content_length(_client));

        if(status == 200)
        {
            ESP_LOGI(tag, "%s -> Successfully posted the temperature and humidity to the server with a status code of -> %d", __func__, status);
        }
        else
        {
            ESP_LOGI(tag, "%s -> Failed to post the temp & humidity to the server with a status code of -> %d", __func__, status);
        }
    }
    else if(result == ESP_ERR_HTTP_FETCH_HEADER)
    {
        ESP_LOGI(tag, "%s -> Successfully posted the temperature and humidity to the server", __func__);
    }
    else 
    {
        ESP_LOGI(tag, "%s -> Failed to post the temp & humidity to the server reason: %s", __func__, esp_err_to_name(result));
        _server_state = UNREACHABLE;
    }

    cJSON_free(body);
    cJSON_Delete(doc);
}

/**
 * Configures the http client's configuration.
 */
void Network::configure_client_config()
{
    ESP_LOGI(tag, "%s -> Configuring http client's configuration", __func__);

    const auto* config = _device->config();

    _client_config.host = config->host,
    _client_config.port = 3000;
    _client_config.path = "/api";
    _client_config.transport_type = HTTP_TRANSPORT_OVER_TCP;
    _client_config.event_handler = nullptr;
    _client_config.timeout_ms = 4000;
}

/**
 * Configures the device's Wi-Fi connection in station mode, and registers the Wi-Fi event handlers.
 */
void Network::configure_wifi(void)
{
    ESP_LOGI(tag, "%s -> Configuring Device Wi-Fi", __func__);

    _net_state = INITIALIZED;

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();

    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_evt_handler, nullptr));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_evt_handler, nullptr));
    
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(tag, "%s -> Done configuring Wi-Fi, starting Wi-Fi now", __func__);
}

/**
 * Configures the http server.
 */
void Network::configure_server(void) 
{
    ESP_LOGI(tag,"%s -> Configuring the device web server", __func__);

    const httpd_uri_t uri_get_config = {
        .uri = "/config",
        .method = HTTP_GET,
        .handler = on_get_config,
        .user_ctx = nullptr
    };

    const httpd_uri_t uri_post_config = {
        .uri = "/config",
        .method = HTTP_POST,
        .handler = on_post_config,
        .user_ctx = nullptr
    };

    const httpd_uri_t uri_info = {
        .uri = "/info",
        .method = HTTP_GET,
        .handler = on_info,
        .user_ctx = nullptr
    };

    const httpd_uri_t uri_restart = {
        .uri = "/restart",
        .method = HTTP_GET,
        .handler = on_restart,
        .user_ctx = nullptr
    };

    const httpd_uri_t uri_sensor = {
        .uri = "/sensor",
        .method = HTTP_GET,
        .handler = on_sensor,
        .user_ctx = nullptr
    };

    const httpd_uri_t uri_update = {
        .uri = "/update",
        .method = HTTP_GET,
        .handler = on_update,
        .user_ctx = nullptr
    };

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();

    if (httpd_start(&_server, &config) == ESP_OK)
    {
        httpd_register_uri_handler(_server, &uri_get_config);
        httpd_register_uri_handler(_server, &uri_post_config);
        httpd_register_uri_handler(_server, &uri_info);
        httpd_register_uri_handler(_server, &uri_restart);
        httpd_register_uri_handler(_server, &uri_sensor);
        httpd_register_uri_handler(_server, &uri_update);
    }

    ESP_LOGI(tag,"%s -> Finished configuring device web server", __func__);
}

/**
 * Attempts to reconnect to the Wi-Fi.
 */
void Network::reconnect_wifi(void)
{
    ESP_LOGI(tag, "%s -> Attempting to reconnect to the router", __func__);

    if(_retries < _max_retries)
    {
        esp_wifi_connect();
        _retries++;
    }
    else
    {
        ESP_LOGI(tag, "%s -> Failed to reconnect to the router", __func__);

        if(connect_interval == 50000)
        {
            _reconnect = false;
            _device->restart(1000);
            return;
        }

        connect_interval += 1000;
        _retries = 0;
    }

    vTaskDelay(connect_interval / portTICK_PERIOD_MS);
}

/**
 * Initializes the HTTP client, sets the server-required headers, sets the URL, 
 * sets the http method, and then executes the http request.
 * @param path The path to the API endpoint.
 * @param body The body of the request.
 * @param method The http method i.e HTTP_METHOD_GET, HTTP_METHOD_POST etc.
 * @return
 *     - ESP_OK on success.
 *     - ESP_FAIL on error.
 */
esp_err_t Network::send_req(const char *path, const char *body, const esp_http_client_method_t method)
{
    if(_client != nullptr) esp_http_client_cleanup(_client);

    const auto *config = _device->config();

    _client = esp_http_client_init(&_client_config);

    char *encrypted_key = nullptr;

    auto result = _device->encrypt(const_cast<char*>(x_key), &encrypted_key);

    if(result != ESP_OK)
    {
        ESP_LOGE(tag, "%s -> Failed to encrypt api key -> %s", __func__, esp_err_to_name(result));
        return result;
    }

    ESP_LOGI(tag, "%s -> Encrypted key api key -> %s", __func__, encrypted_key);

    char *encrypted_id = nullptr;

    result = _device->encrypt(const_cast<char*>(config->uuid), &encrypted_id);

    if(result != ESP_OK)
    {
        ESP_LOGE(tag, "%s -> Failed to encrypt device id -> %s", __func__, esp_err_to_name(result));
        free(encrypted_key);
        return result;
    }

    ESP_LOGI(tag, "%s -> Encrypted id is  -> %s", __func__, encrypted_id);

    result = esp_http_client_set_header(_client, "x-dev-key", encrypted_key);

    if(result != ESP_OK)
    {
        ESP_LOGE(tag, "%s -> Failed to set x-dev-key header, reason -> %s", __func__, esp_err_to_name(result));
        goto fail;
    }

    result = esp_http_client_set_header(_client, "x-dev-id", encrypted_id);

    if(result != ESP_OK)
    {
        ESP_LOGE(tag, "%s -> Failed to set x-dev-id header, reason -> %s", __func__, esp_err_to_name(result));
        goto fail;
    }

    result = esp_http_client_set_url(_client, path);

    if(result != ESP_OK)
    {
        ESP_LOGE(tag, "%s -> Failed to set http url, reason: %s", __func__, esp_err_to_name(result));
        goto fail;
    }

    result = esp_http_client_set_method(_client, method);

    if(result != ESP_OK)
    {
        ESP_LOGE(tag, "%s -> Failed to set http method, reason: %s", __func__, esp_err_to_name(result));
        goto fail;
    }

    if(method == HTTP_METHOD_POST)
    {
        result = esp_http_client_set_header(_client, "Content-Type", "application/json");

        if(result != ESP_OK)
            ESP_LOGE(tag, "%s -> Failed to Content-Type header reason: %s", __func__, esp_err_to_name(result));

        result = esp_http_client_set_post_field(_client, body, strlen(body));
        
        if(result != ESP_OK)
        {
            ESP_LOGI(tag, "%s -> Failed to set post field reason is: %s", __func__, esp_err_to_name(result));
            goto fail;
        }
    }

    ESP_LOGI(tag, "%s -> Performing http client call", __func__);

    free(encrypted_key);
    free(encrypted_id);

    return esp_http_client_perform(_client);

fail:
    ESP_LOGI(tag, "%s -> Reached fail", __func__);

    if(encrypted_key != nullptr) 
        free(encrypted_key);
    
    if(encrypted_key != nullptr)
        free(encrypted_id);

    return result;
}

/**
 * Gets the device MAC address and stores it in the _mac variable.
 * @return
 *    - ESP_OK Success.
 *    - ESP_FAIL Failed to get mac.
 */
esp_err_t Network::get_mac(void)
{
    ESP_LOGI(tag,"%s -> Getting Device Mac Address", __func__);

    uint8_t mac_byte_buffer[6]{};

    const auto status = esp_efuse_mac_get_default(mac_byte_buffer);
    
    if(status == ESP_OK)
    {
        snprintf(_mac, sizeof(_mac), "%02X%02X%02X%02X%02X%02X",
            mac_byte_buffer[0], mac_byte_buffer[1],
            mac_byte_buffer[2], mac_byte_buffer[3],
            mac_byte_buffer[4], mac_byte_buffer[5]);
    }

    ESP_LOGI(tag,"%s -> Device Mac Address is -> %s", __func__, _mac);

    return status;
}

/**
 * Monitors that the server is up, running and reachable by a sending a 
 * GET request to the server and updates the server state accordingly
 */
void Network::on_update_state(void)
{
  ESP_LOGI(tag, "%s -> Pinging the server", __func__);

  const auto result = send_req("/api/ping", nullptr, HTTP_METHOD_GET);

  if(result == ESP_OK)
  {
    ESP_LOGI(tag, "%s -> Server status is reachable", __func__);

    if(!_get_key && !_got_key) _get_key = true;

    _server_state = REACHABLE;
  }
  else
  {
    _server_state = UNREACHABLE;
    ESP_LOGI(tag, "%s -> Server status is unreachable due to -> %s", __func__, esp_err_to_name(result));
  }
}

/**
 * Gets the api key from the server which is used to validate the authentication.
 * of requests made to this device's http server.
 */
void Network::get_key(void)
{
    ESP_LOGI(tag, "%s -> Fetching api key from the server", __func__);

    const auto result = send_req("/api/key", nullptr, HTTP_METHOD_GET);

    if(result == ESP_OK) 
    {
	    const auto status = esp_http_client_get_status_code(_client);

        if(status != 200)
        {
            ESP_LOGI(tag, "%s -> Failed to get api key with status code of -> %d", __func__, status);
            return;
        }

        ESP_LOGI(tag, "%s -> Http status code -> %d", __func__, status);

	    const auto len = esp_http_client_get_content_length(_client);

        ESP_LOGI(tag, "%s -> Http content len -> %d", __func__, len);

        auto* buf = static_cast<char *>(malloc(static_cast<size_t>(len)));

	    const auto read_size = esp_http_client_read(_client, buf, len);

        ESP_LOGI(tag, "%s ->  Http read size -> %d, data read -> %s", __func__, read_size, buf);

        if(read_size > 0)
        { 
            ESP_LOGI(tag, "%s -> Http receive buffer -> %s with sizeof -> %d", __func__, buf, read_size);

            auto obj = cJSON_Parse(buf);

            auto *data = cJSON_GetObjectItem(obj, "data")->valuestring;

            char *decrypted_key = nullptr;

            auto ret = _device->decrypt(data, &decrypted_key);

            if(ret != ESP_OK)
            {
                ESP_LOGE(tag, "%s -> Failed to decrypt api key because -> %s", __func__, esp_err_to_name(ret));
            }
            else
            {
                strcpy(_api_key, decrypted_key);
                ESP_LOGI(tag, "%s -> Got api key -> %s", __func__, _api_key);
                _got_key = true;
            }

            free(decrypted_key);
            cJSON_Delete(obj);
        }
        else
            ESP_LOGI(tag, "%s -> Couldn't get api key, response has empty data", __func__);

        if(_server_state != REACHABLE) _server_state = REACHABLE;

        free(buf);
    }
    else
    {
        ESP_LOGE(tag, "%s -> Error perform http request -> %s", __func__, esp_err_to_name(result));

        if(result == ESP_ERR_HTTP_CONNECT)
        {
            _server_state = UNREACHABLE;
            _get_key = false;
        }        
    }
}

/**
 * Setup the http server and connect to the Wi-Fi.
 */
void Network::init(Led *led)
{
    ESP_LOGI(tag,"%s -> Initializing class", __func__);

    _device = Device::instance();

    _sensor = new Sensor(GPIO_NUM_4);

    ESP_ERROR_CHECK_WITHOUT_ABORT(_sensor->init());

    _led = led;

    ESP_ERROR_CHECK(esp_netif_init());

    if(_device->configured())
        configure_server();

    configure_wifi();

    get_mac();

    ESP_LOGI(tag,"%s -> Finished initializing class", __func__);
}

/**
 * Loop function.
 * Handles obtaining the API key, reconnecting to Wi-Fi, and uploading sensor data to a server.
 */
void Network::handle(void)
{
    if(_reconnect) reconnect_wifi();

    if(_net_state != CONNECTED) return;

    if(millis() - _last_ping > _ping_interval)
    {
        on_update_state();
        _last_ping = millis();
    }

    if(_server_state == UNREACHABLE) return;

    if(_get_key && !_got_key) get_key();

    if(millis() - _last_sync > _sensor_sync)
    {
        on_send();
        _last_sync = millis();
    }
}