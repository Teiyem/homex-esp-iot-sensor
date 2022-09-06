#include "device.h"

/* Singleton instance of the Device class. */
Device *Device::_instance = nullptr;
 
/* Configuration of the device. */
device_config_t Device::_config{};

/* Indicates whether or not the clock should be set. */
std::atomic_bool Device::_set_clock{false};

/* Indicates whether or not the device should be restarted. */
std::atomic_bool Device::_should_restart{false};

/* Milliseconds used to delay the restart of the device. */
std::atomic_uint16_t Device::_restart_delay{200};

/* Total amount of storage available. */
size_t   Device::_storage_available;

 /* Total Amount of storage used. */
size_t   Device::_storage_used;

/* A pointer to the start of the encryption and decryption key. */
extern const uint8_t crypt_key_start[] asm("_binary_crypt_key_start");

/* A pointer to the end of the encryption and decryption key. */
extern const uint8_t crypt_key_end[] asm("_binary_crypt_key_end");

/* A macro aligns the length of the data to 4 bytes. */
#define ALIGN_LEN(x)	(((x) + 3) & ~3u)

/* A macro that calculates the length of the encoded data. */
#define ENCODE_LEN(x)	((((x) + 2) / 3) * 4 + 1)

/* A macro that calculates the length of the decoded data. */
#define DECODE_LEN(x)	(ALIGN_LEN(x) / 4 * 3 + 1)

/**
 * Get the Device class instance. 
 * @return A pointer to the Device class instance.
 */
Device *Device::instance(void)
{
    if(_instance == nullptr)
    { 
        _instance = new Device();
    }

	return _instance;
}

/**
 * Mounts the SPIFFS filesystem and keeps track of total and used storage space.
 * @return
 *    - ESP_OK Success.
 *    - ESP_FAIL Failed to mount or read storage info.
 */
esp_err_t Device::mount_storage(void)
{
    ESP_LOGI(tag, "%s ->  Mounting Device Storage", __func__);

    auto result = ESP_OK;

    const esp_vfs_spiffs_conf_t conf = {
        .base_path = "/spiffs",
        .partition_label = "storage",
        .max_files = 5,
        .format_if_mount_failed = false // Change to true when uploading for the first time.
    };

    result = esp_vfs_spiffs_register(&conf);
                
    if (result != ESP_OK) 
        return result;

    result = esp_spiffs_info(conf.partition_label, &_storage_available, &_storage_used);
        
    if (result != ESP_OK) 
    {
        ESP_LOGE(tag, "%s ->  Failed to get device filesystem information -> %s", __func__, esp_err_to_name(result));
        return result;
    }

    ESP_LOGI(tag, "%s ->  Device Storage Size: Total -> %d Bytes, Used -> %d Bytes", __func__, _storage_available, _storage_used);

    return result;
}

/**
 * Reads the device configuration from the filesystem.
 * @return
 *    - ESP_OK Success.
 *    - ESP_FAIL Failed to read.
 */
esp_err_t Device::read_config(void)
{
    ESP_LOGI(tag, "%s -> Fetching device configuration from storage", __func__);

    auto result = ESP_OK;

    auto *file = fopen(_config_path, "r");

    result = file == nullptr ? ESP_FAIL : ESP_OK;

    if (result != ESP_OK) 
        return result;

    ESP_LOGI(tag, "%s -> Configuration file loaded, now reading from configuration file", __func__);

    char buf[300] = {};

    fread(buf, 1, sizeof(buf), file);

    ESP_LOGI(tag, "%s -> Read a total of -> %d bytes", __func__, sizeof(buf));

    ESP_LOGI(tag, "%s -> Configuration file contains -> %s", __func__, buf);

    auto *obj = cJSON_Parse(buf);

    strcpy(_config.name, cJSON_GetObjectItem(obj, "name")->valuestring);
    strcpy(_config.sta_ssid, cJSON_GetObjectItem(obj, "sta_ssid")->valuestring);
    strcpy(_config.sta_pass, cJSON_GetObjectItem(obj, "sta_pass")->valuestring);
    strcpy(_config.host, cJSON_GetObjectItem(obj, "host")->valuestring);
    strcpy(_config.uuid, cJSON_GetObjectItem(obj, "uuid")->valuestring);
    
    cJSON_Delete(obj);
    fclose(file);

    ESP_LOGI(tag, "%s -> Finished fetching device configuration from storage", __func__);

    return result;
}

/**
 * Reads the device info from the filesystem.
 * @param doc The JSON document to store the data in.
 * @param mac The device's mac address.
 * @return
 *    - ESP_OK Success.
 *    - ESP_FAIL Failed to read.
 */
esp_err_t Device::read_info(char *obj, const char *mac)
{
    ESP_LOGI(tag, "%s -> Fetching device information from storage", __func__);

    auto *file = fopen(_info_path, "r");

    auto result = file == nullptr ? ESP_FAIL : ESP_OK;

    if (result != ESP_OK) 
        return result;

    ESP_LOGI(tag, "%s -> Device information file loaded, now reading from information file", __func__);

    char buf[500] = {};

    fread(buf,1,sizeof(buf), file);

    ESP_LOGI(tag, "%s -> Read a total of -> %d bytes", __func__, sizeof(buf));

    ESP_LOGI(tag, "%s -> Device information file contains: -> %s", __func__, buf);

    auto *json = cJSON_Parse(buf);

    cJSON_AddNumberToObject(json, "heap", esp_get_free_heap_size());
    cJSON_AddStringToObject(json, "mac", mac);
    cJSON_AddNumberToObject(json, "storage available", static_cast<double>(_storage_available));
    cJSON_AddNumberToObject(json, "storage used", static_cast<double>(_storage_used));
    
    auto *info = cJSON_Print(json);

    strcpy(obj, info);

    cJSON_free(info);
    cJSON_Delete(json);
    fclose(file);

    ESP_LOGI(tag, "%s -> Finished fetching device information from storage", __func__);

    return result;
}

/**
 * Writes the device configuration to the filesystem.
 * @param config The device configuration to write.
 * @return
 *    - ESP_OK Success.
 *    - ESP_FAIL Failed to write.
 */
esp_err_t Device::write_config(const device_config_t config)
{
    ESP_LOGI(tag,"%s -> Writing new device configuration to storage", __func__);

    _config = config;

    auto *file = fopen(_config_path, "w");

    auto result = file == nullptr ? ESP_FAIL : ESP_OK;

    if (result != ESP_OK)
        return result;

    ESP_LOGI(tag,"%s -> Device configuration file opened, proceeding to write to file", __func__);

    auto *obj = cJSON_CreateObject();

    cJSON_AddStringToObject(obj, "name", _config.name);
    cJSON_AddStringToObject(obj, "sta_ssid", _config.sta_ssid);
    cJSON_AddStringToObject(obj, "sta_pass", _config.sta_pass);
    cJSON_AddStringToObject(obj, "host", _config.host);
    cJSON_AddStringToObject(obj, "uuid", _config.uuid);

    auto *buf = cJSON_Print(obj);

    fprintf(file, buf);
    fclose(file);
    
    cJSON_free(buf);
    cJSON_Delete(obj);

    ESP_LOGI(tag,"%s -> Finished writing new device configuration to storage", __func__);

    return result;
}

/**
 * Encrypts string data
 * @param data The data to be encrypted
 * @param encrypted The encrypted data
 * @return
 *    - ESP_OK Success.
 *    - ESP_FAIL Failed to encrypt.
 *    - ESP_ERR_INVALID_ARG Invalid input data.
 */
esp_err_t Device::encrypt(char *data, char **encrypted)
{
    const auto len = strlen(data);

    if(!data || len == 0)
    {
        ESP_LOGW(tag, "%s -> Invalid data passed with -> %d@%p", __func__, len, data);
        return ESP_ERR_INVALID_ARG;
    }

    auto result = ESP_FAIL;

    const uint8_t *key = const_cast<uint8_t *>(crypt_key_start);

    ESP_LOGI(tag, "%s -> Encrypting data with key -> %s", __func__, key);

    uint8_t iv[16]{};

    for (auto &i : iv)
    {
	    i = static_cast<uint8_t>(esp_random());
    }

	ESP_LOGI(tag, "%s -> Encryption Iv is -> %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", __func__,
	        iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6], iv[7], iv[8], iv[9], iv[10], iv[11], iv[12], iv[13],
	        iv[14], iv[15]);

    auto block_length  = len;

    if(block_length % 16) 
    {
        block_length  += 16 - (len % 16);
        
        ESP_LOGI(tag, "%s -> Input data length -> %d, added padding length of -> %d", __func__, len, block_length );
    }

    const auto output = static_cast<uint8_t *>(malloc(block_length ));

    if(output == nullptr)
    {
        ESP_LOGI(tag,"%s -> Failed to allocate memory for output buffer", __func__);
        return ESP_FAIL;
    }

    memset(output, 0, block_length );

    size_t enc_len = 0;

    const mbedtls_cipher_info_t *cipher_info = const_cast<mbedtls_cipher_info_t *>(mbedtls_cipher_info_from_type(
	    MBEDTLS_CIPHER_AES_256_CBC));

    mbedtls_cipher_context_t ctx;

    mbedtls_cipher_init(&ctx);

    auto ret = mbedtls_cipher_setup(&ctx, cipher_info);

    if(ret)
    {
        ESP_LOGI(tag,"%s -> mbedtls_cipher_setup failed reason -0x%04X", __func__, -ret);
        free(output);
        return result;
    }

    ret = mbedtls_cipher_setkey(&ctx, key, cipher_info->key_bitlen, MBEDTLS_ENCRYPT);

    if(ret)
    {
        ESP_LOGI(tag,"%s -> mbedtls_cipher_setkey failed reason -0x%04X", __func__, -ret);
        free(output);
        return result;
    }

    ret = mbedtls_cipher_crypt(&ctx, iv, 16, reinterpret_cast<uint8_t *>(data), len, output, &enc_len);

    if(ret)
    {
        ESP_LOGI(tag,"%s -> mbedtls_cipher_crypt failed reason -0x%04X", __func__, -ret);
        free(output);
        return result;
    }

    ESP_LOGI(tag,"%s -> Encrypted data size -> %d", __func__, enc_len);

    constexpr size_t iv_base64_len = ENCODE_LEN(16);

    const size_t data_base64_len = ENCODE_LEN(enc_len);

    const auto encoded_iv = static_cast<char *>(malloc(iv_base64_len));

    const auto encoded_data = static_cast<char *>(malloc(data_base64_len));

    if(encoded_iv == nullptr || encoded_data == nullptr)
    {
        ESP_LOGE(tag,"%s -> Failed to allocated mem for encoded iv or encoded data", __func__);
        free(output);
        return result;
    }

    size_t iv_enc_len;

    size_t sec_enc_len;

    ret = mbedtls_base64_encode(reinterpret_cast<uint8_t*>(encoded_iv), iv_base64_len, &iv_enc_len, iv, 16);

    if(ret)
    {
        ESP_LOGI(tag,"%s -> Failed to encode Iv reason -0x%04X", __func__, -ret);
        free(output);
        free(encoded_iv);
        free(encoded_data);
        return result;
    }

    ret = mbedtls_base64_encode(reinterpret_cast<uint8_t*>(encoded_data), data_base64_len, &sec_enc_len, output, enc_len);

    if(ret)
    {
        ESP_LOGI(tag,"%s -> Failed to encode data reason -0x%04X", __func__, -ret);
        free(output);
        free(encoded_iv);
        free(encoded_data);
        return result;
    }

    ESP_LOGI(tag,"%s -> Done encoding. Encoded Iv size -> %d and Encoded encrypted data size -> %d", __func__, iv_enc_len, sec_enc_len );

    char final_str[500]{};

    strcpy(final_str, encoded_iv);
    strcat(final_str, "]");
    strcat(final_str, encoded_data);

    *encrypted = (char *)malloc(strlen(final_str)); 
    strcpy(*encrypted, final_str);

    free(output);
    free(encoded_iv);
    free(encoded_data);

    ESP_LOGI(tag, "%s -> Done encrypting and encoding data from -> %s to -> %s", __func__, data, final_str);

    mbedtls_cipher_free(&ctx);

    return ESP_OK;
}

/**
 * Decrypts string data
 * @param data The base64 string data to decrypt
 * @param decrypted The decrypted string data
 * @return
 *    - ESP_OK Success.
 *    - ESP_FAIL Failed to encrypt.
 *    - ESP_ERR_INVALID_ARG Invalid input data.
 */
esp_err_t Device::decrypt(char *data, char **decrypted)
{
    const auto len = strlen(data);

    if(!data || len == 0)
    {
        ESP_LOGE(tag, "%s -> Invalid data passed with -> %d@%p", __func__, len, data);
        return ESP_ERR_INVALID_ARG;
    }

    const uint8_t *key = const_cast<uint8_t*>(crypt_key_start);

    ESP_LOGI(tag, "%s -> Decrypting data with key -> %s", __func__, key);

    auto result = ESP_FAIL;

    char *encoded_iv = strtok(data, "]");

    char *encoded_data = strtok(nullptr, "");

    if(!encoded_iv || !encoded_data)
    {
        ESP_LOGE(tag,"%s -> %s is invalid data", __func__, data);
        return result;
    }

    ESP_LOGI(tag, "%s -> Encoded Iv is -> %s and Encoded encrypted data is -> %s", __func__, encoded_iv, encoded_data);

    const auto iv_len = strlen(encoded_iv);

    const auto data_len = strlen(encoded_data);

    const size_t dec_iv_len = DECODE_LEN(iv_len);

    size_t dec_data_len = DECODE_LEN(data_len);

    const auto iv = static_cast<char *>(malloc(dec_iv_len));

    const auto decoded_data = static_cast<char *>(malloc(dec_data_len));

    if(!iv || !decoded_data)
    {
        ESP_LOGE(tag,"%s -> Failed to allocated mem for decoded iv or decoded data", __func__);
        return result;
    }

    const size_t iv_align_len = ALIGN_LEN(iv_len);

    const size_t data_align_len = ALIGN_LEN(data_len);

    const auto iv_tmp = static_cast<uint8_t *>(malloc(iv_align_len + 1));

    const auto data_tmp = static_cast<uint8_t *>(malloc(data_align_len + 1));

    if(!iv_tmp || !data_tmp)
    {
        ESP_LOGE(tag,"%s -> Failed to allocated mem for temp iv buffer or temp data buffer", __func__);
        return result;
    }

    memcpy(iv_tmp, encoded_iv, iv_len);
    memcpy(data_tmp, encoded_data, data_len);

    for (auto i = iv_len; i < iv_align_len; i++) {
		iv_tmp[i] = '=';
	}
	iv_tmp[iv_align_len] = '\0';

    for (auto i = data_len; i < data_align_len; i++) {
		data_tmp[i] = '=';
	}
	data_tmp[data_align_len] = '\0';

    size_t iv_out_len;

    size_t data_out_len;

    auto ret = mbedtls_base64_decode(reinterpret_cast<uint8_t *>(iv), dec_iv_len, &iv_out_len, iv_tmp, iv_align_len);

    if(ret)
    {
        ESP_LOGI(tag,"%s -> Failed to decode Iv reason -0x%04X", __func__, -ret);
        free(iv_tmp);
        free(data_tmp);
        return result;
    }

	mbedtls_base64_decode(reinterpret_cast<uint8_t*>(decoded_data), dec_data_len, &data_out_len, data_tmp,
	        data_align_len);

    if(ret)
    {
        ESP_LOGI(tag,"%s -> Failed to decode Iv reason -0x%04X", __func__, -ret);
        free(iv_tmp);
        free(data_tmp);
        return result;
    }

	ESP_LOGI(tag, "%s -> Decoded Iv size -> %d and Decoded encrypted data size -> %d", __func__, iv_out_len,
	        data_out_len);

	ESP_LOGI(tag, "%s -> Encryption Iv is %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", __func__,
	        iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6], iv[7], iv[8], iv[9], iv[10], iv[11], iv[12], iv[13],
	        iv[14], iv[15]);

    free(iv_tmp);
    free(data_tmp);

    dec_data_len = data_out_len;

    const auto output = static_cast<uint8_t *>(malloc(dec_data_len));

    memset(output, 0, dec_data_len);

    size_t decrypt_out_len = 0;

    const mbedtls_cipher_info_t* cipher_info = const_cast<mbedtls_cipher_info_t*>(mbedtls_cipher_info_from_type(
	    MBEDTLS_CIPHER_AES_256_CBC));
    
    mbedtls_cipher_context_t ctx;
    
    mbedtls_cipher_init(&ctx);

    mbedtls_cipher_setup(&ctx, cipher_info);

    mbedtls_cipher_setkey(&ctx, key, cipher_info->key_bitlen, MBEDTLS_DECRYPT);

    mbedtls_cipher_crypt(&ctx, reinterpret_cast<uint8_t *>(iv), 16, reinterpret_cast<uint8_t*>(decoded_data), dec_data_len, output, &decrypt_out_len);

    size_t out_len = decrypt_out_len; 

    auto padding = ctx.get_padding(output, dec_data_len, &out_len);

    ESP_LOGI(tag, "%s -> Data contains padding -> %s of size -> %d", __func__, padding == 0 ? "true":"false", out_len);

    if(padding == 0) output[out_len] = '\0';

    ESP_LOGI(tag, "%s -> Done Decrypting data. Data size is -> %d and data contains -> %s", __func__, decrypt_out_len, output);

    char final_str[500]{};

    strcpy(final_str, reinterpret_cast<char*>(output));

    *decrypted = static_cast<char*>(malloc(strlen(final_str)));
    strcpy(*decrypted, final_str);

    free(iv);
    free(decoded_data);
    free(output);

    mbedtls_cipher_free(&ctx);

    return ESP_OK;
}

/**
 * Sets the device to restart and sets the restart delay to the delay passed in.
 * @param delay The delay in milliseconds before the device restarts.
 */
void Device::restart(const uint16_t delay)
{
    _restart_delay = delay;
    _should_restart = true;
}

/**
 * Sets the set clock flag to true. 
 */
void Device::set_clock(void)
{
    _set_clock = true;
}

/**
 * Checks whether the length of the station SSID or password is qual to zero.
 * @return
 *     - true The device is configured.
 *     - false The device is not configured.
 */
bool Device::configured(void)
{
    if(strlen(_config.sta_ssid) == 0 || strlen(_config.sta_pass) == 0)
        return false;

    return true;
}

/**
 * Gets a string representation of the current time, as determined by the device's internal clock.
 * @return A time string pointer.
 */
const char* Device::now_to_str(void)
{
    const std::time_t time_now{std::chrono::system_clock::to_time_t(now())};
    return std::asctime(std::localtime(&time_now));
}

/**
 * Callback handler for time synchronization notifications, 
 * Sets the device's time to the time received from the server.
 */
void Device::on_time_sync(timeval *tv)
{
   settimeofday(tv, nullptr);
   ESP_LOGI(tag, "%s ->  Current time is -> %s", __func__, _instance->now_to_str());
   sntp_set_sync_status(SNTP_SYNC_STATUS_COMPLETED);
}

/** 
 * A workaround for storing one-time data in spiffs. I couldn't find a Spiffs 
 * uploader tool for this SDK. 
 */
void Device::write_to_storage(void)
{
    ESP_LOGI(tag, "%s ->  Creating config and info files", __func__);

    auto *config_file = fopen(_config_path, "w");

    if (config_file == nullptr) {
        ESP_LOGE(tag, "%s ->  Failed to open file for writing", __func__);
        return;
    }

	auto *config_obj = cJSON_CreateObject();

    cJSON_AddStringToObject(config_obj, "name", "");
    cJSON_AddStringToObject(config_obj, "sta_ssid", "");
    cJSON_AddStringToObject(config_obj, "sta_pass", "");
    cJSON_AddStringToObject(config_obj, "host", "");
    cJSON_AddStringToObject(config_obj, "uuid", "hx-iot-esVwDiKeQj");

	auto *config_result = cJSON_Print(config_obj);

    fprintf(config_file, config_result);
        
    fclose(config_file);

	ESP_LOGI(tag, "%s ->  Configuration File Display\n%s", __func__,  config_result);

	cJSON_Delete(config_obj);
	cJSON_free(config_result);

    ESP_LOGI(tag, "%s -> Creating config and info files.....", __func__);

    auto *info_file = fopen(_info_path, "w");

    if (info_file == nullptr) {
        ESP_LOGE(tag, "%s -> Failed to open file for writing", __func__);
        return;
    }

	auto *info_obj = cJSON_CreateObject();

    cJSON_AddStringToObject(info_obj, "firmware", "hx-iot");
    cJSON_AddStringToObject(info_obj, "type", "climate-sensor");
    cJSON_AddStringToObject(info_obj, "hardware", "esp8266");

    auto *attr_obj = cJSON_AddArrayToObject(info_obj, "attributes");

    auto *attr1 = cJSON_CreateObject();
    cJSON_AddStringToObject(attr1, "name", "temp");
    cJSON_AddStringToObject(attr1, "value", "int");
	cJSON_AddItemToArray(attr_obj, attr1);

    auto *attr2 = cJSON_CreateObject();
    cJSON_AddStringToObject(attr2, "name", "humidity");
    cJSON_AddStringToObject(attr2, "value", "int");
	cJSON_AddItemToArray(attr_obj, attr2);

	auto *info_result = cJSON_Print(info_obj);

    fprintf(info_file, info_result);
    fclose(info_file);

	ESP_LOGI(tag, "%s -> Info File Display\n%s", __func__, info_result);

	cJSON_Delete(info_obj);
	cJSON_free(info_result);

}

/**
 * Configures the timezone and the sntp time server.
 */
void Device::config_sntp(void)
{
    ESP_LOGI(tag, "%s ->  Initializing SNTP", __func__);

    setenv("TZ", "GMT-2", 1);
    tzset();

    sntp_setoperatingmode(SNTP_OPMODE_POLL);
    sntp_setservername(0, "time.google.com");
    sntp_setservername(1, "pool.ntp.com");
    sntp_set_time_sync_notification_cb(on_time_sync);
    sntp_set_sync_interval(_clock_sync_time);

    sntp_init();

    _clock_set = true;

    ESP_LOGI(tag, "%s ->  Done initializing SNTP", __func__);
}

/**
 * Restarts the device.
 */
void Device::restart(void)  
{
    ESP_LOGI(tag, "%s -> Restarting device", __func__);
    vTaskDelay(_restart_delay/ portTICK_PERIOD_MS);
    esp_restart();
}

/**
 * Initializes the NVS flash, creates the default event loop, mounts the storage
 * and reads the configuration file.
 */
void Device::init(void)
{
    ESP_LOGI(tag, "%s -> Initializing class", __func__);

    ESP_LOGI(tag, "%s ->  Initializing NVS Flash", __func__);

    auto result = nvs_flash_init();

    if(result != ESP_OK)
        ESP_LOGE(tag, "%s ->  Failed To Initialize NVS Flash", __func__);

    ESP_LOGI(tag, "%s ->  Creating Default Event loop", __func__);

    result = esp_event_loop_create_default();

    if(result != ESP_OK)
            ESP_LOGE(tag, "%s ->  Failed To Create Default Event loop", __func__);

    result = mount_storage();

    if (result != ESP_OK)
    {
        if (result == ESP_FAIL)
            ESP_LOGE(tag, "%s ->  Failed to Mount Device Filesystem", __func__);

        else if (result == ESP_ERR_NOT_FOUND)
            ESP_LOGE(tag, "%s ->  Failed to Find Device Filesystem", __func__);

        else
            ESP_LOGE(tag, "%s ->  Failed To Initialize Device Filesystem reason -> %s", __func__,  esp_err_to_name(result));
        
        _restart_delay = 1000;
        restart();
    }

    //write_to_storage();

    result = read_config();

    if(result != ESP_OK)
    {
        ESP_LOGE(tag, "%s ->  Failed to open configuration file", __func__);
        _restart_delay = 1000;
        restart();
    }

    ESP_LOGI(tag, "%s ->  Done initializing class", __func__);
}

/**
 * Loop function.
 * Handles restarting the device and configuring the sntp.
 */
void Device::handle(void)
{
    if(_should_restart) restart();

    if(_set_clock && !_clock_set) config_sntp();
}
