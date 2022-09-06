#include "sensor.h"

/**
 * Initializes the DHT sensor.
 * @return The result of the init operation
 *    - ESP_OK Success
 *    - ESP_ERR_INVALID_ARG Parameter error
 *    - ESP_FAIL Init error
 */
esp_err_t Sensor::init()
{
    ESP_LOGI(tag, "%s Initializing dht sensor", __func__);
    return dht_init(_dht_pin, true);
}

/**
 * Reads the temperature and humidity from the DHT22 sensor and stores the values in the
 * pointers passed to it.
 * @param temp Pointer where the temperature value will be stored.
 * @param humidity Pointer where the humidity value will be stored.
 * @return
 *    - ESP_OK Success.
 *    - ESP_FAIL Failed to read.
 */
esp_err_t Sensor::read(int16_t *temp, int16_t *humidity)
{
    ESP_LOGI(tag, "%s Reading temperature and humidity data", __func__);

    int16_t _temp;
    int16_t _humidity;

    esp_err_t status{ESP_FAIL};

    status = dht_read_data(DHT_TYPE_DHT22, _dht_pin, &_humidity, &_temp);

    if(status == ESP_OK)
    {
      *temp = static_cast<int16_t>(_temp / 10);
      *humidity = static_cast<int16_t>(_humidity / 10);

      ESP_LOGI(tag, "%s The Current temperature is %d and humidity is %d", __func__, *temp, *humidity);
    }

    return status;
}