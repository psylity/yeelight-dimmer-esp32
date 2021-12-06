idf_component_register(SRCS "yeelight_dimmer.c"
                    INCLUDE_DIRS "include"
                    REQUIRES hci_common_component mbedtls
                    PRIV_REQUIRES freertos nvs_flash bt esp32)
