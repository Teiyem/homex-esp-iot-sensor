#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "device.h"
#include "network.h"

/* A constant used to identify the source of the log message of this file. */
static constexpr const char *tag = "main";

/* A singleton class that handles device-related tasks. */
Device *device;

/* A singleton class that handles network-related tasks. */
Network *network;

/* A class that handles led-related tasks. */
Led *led;

/**
 * Called by the FreeRTOS scheduler to run the device task.
 * @param param Parameter that is passed to the task.
 */
void IRAM_ATTR device_task(void *param)
{
	ESP_LOGI(tag, "%s -> Device Task running", __func__);

	uint32_t last_check = 0;
	uint32_t check_period = 8000;

	while (true)
	{
		device->handle();
		vTaskDelay(400 / portTICK_PERIOD_MS);
	}
}

/**
 * Called by the FreeRTOS scheduler to run the network task.
 * @param param Parameter that is passed to the task.
 */
void IRAM_ATTR network_task(void *param)
{
	ESP_LOGI(tag, "%s -> Network Task running", __func__);

	uint32_t last_check = 0;
	uint32_t check_period = 8000;

	while (true)
	{
		network->handle();
		vTaskDelay(400 / portTICK_PERIOD_MS);
	}
}

/**
 * Called by the FreeRTOS scheduler to run the led task.
 * @param param Parameter that is passed to the task.
 */
void IRAM_ATTR led_task(void *param)
{
	ESP_LOGI(tag, "%s -> Led Task running", __func__);

	while (true)
	{
		led->handle();
		vTaskDelay(600 / portTICK_PERIOD_MS);
	}
}

/**
 * Application entry point.
 */
extern "C" void app_main()
{
	ESP_LOGI(tag, "%s -> Application starting.....", __func__);

	device = Device::instance();
	network = Network::instance();

	led = new Led(GPIO_NUM_16, true);

	led->init();
	led->toggle(true);
	led->set_mode(SLOW_BLINK);

	device->init();
	network->init(led);

	xTaskCreate(device_task, "device_task", 9000, nullptr, 4, nullptr);
	xTaskCreate(network_task, "network_task", 9000, nullptr, 6, nullptr);
	xTaskCreate(led_task, "led_task", 4000, nullptr, 1, nullptr);

	ESP_LOGI(tag, "%s -> Exiting, switching to tasks", __func__);
}