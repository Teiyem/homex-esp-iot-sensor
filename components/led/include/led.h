#pragma once

#include "esp_log.h"
#include "driver/gpio.h"
#include "util.h"

/** A class that handles led-related tasks. */
class Led
{
    public:
    /**
     * Default constructor.
     * @param pin The pin number that the LED is connected to.
     * @param inverted Whether the toggle logic is inverted.
     */
    constexpr Led(const gpio_num_t pin, const bool inverted) :
        _pin{pin},
        _inverted{inverted},
        _cfg{gpio_config_t{
            .pin_bit_mask   = static_cast<uint32_t>(1) << pin,
            .mode           = GPIO_MODE_OUTPUT,
            .pull_up_en     = GPIO_PULLUP_DISABLE,
            .pull_down_en   = GPIO_PULLDOWN_ENABLE,
            .intr_type      = GPIO_INTR_DISABLE
            }, 
        }
    { }

    esp_err_t init(void);

    esp_err_t toggle(const bool state);
    void set_mode(const led_mode_t mode);
    
    /** Get the state of the led. */
    bool state(void) const { return _state; }

    void handle(void);

    private:
        const gpio_num_t _pin;              /** The pin number that the LED is connected to. */
        const bool _inverted;               /** Whether the toggle logic is inverted. */
        bool _state = false;                /** The state of the led. */
        const gpio_config_t _cfg;           /** The Led's GPIO pin configuration. */
        led_mode_t _mode = STATIC;      /** The Led's current mode. */
        uint32_t _last_toggle = 0;          /** The last time the LED was toggled. */
        const uint32_t _slow_blink = 1000;  /** Slow blink rate of the LED. */
        const uint32_t _fast_blink = 300;   /** Fast blink rate of the LED. */

        static constexpr const char *tag = "led"; /* A constant used to identify the source of the log message of this class. */

};