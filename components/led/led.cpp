#include "led.h"

/**
 * Initialize the LED.
 * @return
 *      - ESP_OK Success.
 *      - ESP_ERR_INVALID_ARG GPIO number error.
 */
esp_err_t Led::init(void)
{
    ESP_LOGI(tag, "%s Initializing the class", __func__);

    auto result = gpio_config(&_cfg);

    if (result == ESP_OK)
    {
        result = toggle(_inverted);
    }

    ESP_LOGI(tag, "%s Done initializing the class", __func__);

    return result;
}

/**
 * Set the state of the LED.
 * @param state The state to toggle the LED to.
 * @return
 *      - ESP_OK Success.
 *      - ESP_ERR_INVALID_ARG GPIO number error.
 */
esp_err_t Led::toggle(const bool state)
{
	_state = state;
    ESP_LOGI(tag, "%s Toggling the led %s", __func__, _state? "on" : "off");
	return gpio_set_level(_pin, _inverted ? !state : state);
}

/**
 * Set the mode of the LED.
 * @param mode The mode to use.
 */
void Led::set_mode(const led_mode_t mode)
{
    ESP_LOGI(tag, "%s Setting the led mode", __func__);
    _mode = mode;
}

/**
 * Loop function.
 * Handles toggling the led on or off depending on the current mode.
 */
void Led::handle()
{
    if (_mode == STATIC) return;

    const auto timeout = _mode == SLOW_BLINK ? _slow_blink : _fast_blink;

    if (millis() - _last_toggle > timeout)
    {
	    const auto result = toggle(!_state);

        if (result == ESP_OK)
            _last_toggle = millis();
    }
}