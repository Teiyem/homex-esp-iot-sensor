idf_component_register(SRCS "main.cpp"
        INCLUDE_DIRS "include"
        REQUIRES "freertos" "esp_common" "device" "network" "led")