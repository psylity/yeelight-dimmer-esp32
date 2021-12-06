#include <stdio.h>

#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_bt.h"
#include "bt_hci_common.h"
#include "esp_gap_ble_api.h"

#include "nvs_flash.h"
#include "driver/dac.h"

#include "yeelight_dimmer.h"

yeelight_dimmers_ctx ctx;

static int host_rcv_pkt(uint8_t *data, uint16_t len) {
    yellight_dimmer_check(&ctx, data, len);
    return ESP_OK;
}

static void controller_rcv_pkt_ready(void) {
    printf("controller rcv pkt ready\n");
}

static esp_vhci_host_callback_t vhci_host_cb = {
        controller_rcv_pkt_ready,
        host_rcv_pkt
};

static uint8_t hci_cmd_buf[128];


static void hci_cmd_send_reset(void)
{
    uint16_t sz = make_cmd_reset(hci_cmd_buf);
    esp_vhci_host_send_packet(hci_cmd_buf, sz);
}

static void hci_cmd_send_set_evt_mask(void)
{
    /* Set bit 61 in event mask to enable LE Meta events. */
    uint8_t evt_mask[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20};
    uint16_t sz = make_cmd_set_evt_mask(hci_cmd_buf, evt_mask);
    esp_vhci_host_send_packet(hci_cmd_buf, sz);
}

static void hci_cmd_send_ble_scan_params(void) {
    /* Set scan type to 0x01 for active scanning and 0x00 for passive scanning. */
    uint8_t scan_type = 0x01;

    /* Scan window and Scan interval are set in terms of number of slots. Each slot is of 625 microseconds. */
    uint16_t scan_interval = 0x50; /* 50 ms */
    uint16_t scan_window = 0x30; /* 30 ms */

    uint8_t own_addr_type = 0x00; /* Public Device Address (default). */
    uint8_t filter_policy = 0x00; /* Accept all packets excpet directed advertising packets (default). */
    uint16_t sz = make_cmd_ble_set_scan_params(hci_cmd_buf, scan_type, scan_interval, scan_window, own_addr_type, filter_policy);
    esp_vhci_host_send_packet(hci_cmd_buf, sz);
}

static void hci_cmd_send_ble_scan_start(void)
{
    uint8_t scan_enable = 0x01; /* Scanning enabled. */
    uint8_t filter_duplicates = 0x00; /* Duplicate filtering disabled. */
    uint16_t sz = make_cmd_ble_set_scan_enable(hci_cmd_buf, scan_enable, filter_duplicates);
    esp_vhci_host_send_packet(hci_cmd_buf, sz);
    printf("BLE Scanning started..\n");
}

// you can store dimmer_value in a global variable like this
// or in dimmer->userdata
int dimmer_value = 0;

void onRotate(yeelight_dimmer_t *dimmer, signed char rotation, char state) {
    dimmer_value += rotation;
    if (dimmer_value < 0)
        dimmer_value = 0;
    if (dimmer_value > 255)
        dimmer_value = 255;

    // Setting DAC channel 1 (GPIO25) voltage 0..3.3v
    dac_output_voltage(DAC_CHANNEL_1, dimmer_value);
    printf("%s rotation %i, state=%i, value = %i\n", (char *)dimmer->userdata, rotation, state, dimmer_value);
}
void onClick(yeelight_dimmer_t *dimmer) {
    printf("click\n");
}
void onDoubleClick(yeelight_dimmer_t *dimmer) {
    printf("double click\n");
}
void onMultipleClicks(yeelight_dimmer_t *dimmer, char count) {
    printf("multiple click (%i)\n", count);
}
void onLongPress(yeelight_dimmer_t *dimmer, char count) {
    printf("long press for %i seconds\n", count);
}


void app_main(void)
{
    yeelight_dimmers_init(&ctx);
    ctx.onRotate = onRotate;
    ctx.onClick = onClick;
    ctx.onDoubleClick = onDoubleClick;
    ctx.onMultipleClicks = onMultipleClicks;
    ctx.onLongPress = onLongPress;

    yeelight_dimmers_add(&ctx, "\xF8\x24\x41\x00\x00\x00", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "example unexistent dimmer");
    yeelight_dimmers_add(&ctx, "\xF8\x24\x41\xC5\xA0\xBE", "\xA3\x15\x7D\xDF\xAC\x2A\x30\xA7\xF5\xE3\x38\x54", "main dimmer");

    dac_output_enable(DAC_CHANNEL_1);

    /* Initialize NVS — it is used to store PHY calibration data */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK( ret );
    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();

    ret = esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT);
    if (ret) {
        printf("Bluetooth controller release classic bt memory failed: %s", esp_err_to_name(ret));
        return;
    }

    if ((ret = esp_bt_controller_init(&bt_cfg)) != ESP_OK) {
        printf("Bluetooth controller initialize failed: %s", esp_err_to_name(ret));
        return;
    }

    if ((ret = esp_bt_controller_enable(ESP_BT_MODE_BLE)) != ESP_OK) {
        printf("Bluetooth controller enable failed: %s", esp_err_to_name(ret));
        return;
    }
    // printf("bluetooth enabled\n");
    esp_vhci_host_register_callback(&vhci_host_cb);

    // wait until send_available()
    while (!esp_vhci_host_check_send_available()) {
        vTaskDelay(100 / portTICK_PERIOD_MS);
    }
    hci_cmd_send_reset();
    // printf("hci_cmd_send_reset()\n");

    while (!esp_vhci_host_check_send_available()) {
        vTaskDelay(100 / portTICK_PERIOD_MS);
    }
    hci_cmd_send_set_evt_mask();
    // printf("hci_cmd_send_set_evt_mask()\n");

    while (!esp_vhci_host_check_send_available()) {
        vTaskDelay(100 / portTICK_PERIOD_MS);
    }
    hci_cmd_send_ble_scan_params();
    // printf("hci_cmd_send_ble_scan_params()\n");

    while (!esp_vhci_host_check_send_available()) {
        vTaskDelay(100 / portTICK_PERIOD_MS);
    }
    hci_cmd_send_ble_scan_start();
    // printf("hci_cmd_send_ble_scan_start()\n");

    for (int i = 600; i >= 0; i--) {
        if (i < 30) {
            printf("Restarting in %d seconds...\n", i);
        }
        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }
    printf("Restarting now.\n");
    fflush(stdout);
    esp_restart();
}
