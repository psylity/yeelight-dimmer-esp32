#include <stdint.h>

typedef struct yeelight_dimmer {
    char reversed_mac[6];
    unsigned char decrypt_key[16];
    void *userdata;
    void *next;
} yeelight_dimmer_t;

typedef struct yeelight_dimmers_ctx_s {
    yeelight_dimmer_t *dimmers;

    void (*onRawData)(yeelight_dimmer_t *dimmer, uint8_t *data, unsigned char len);
    void (*onRotate)(yeelight_dimmer_t *dimmer, signed char rotation, char state);
    void (*onClick)(yeelight_dimmer_t *dimmer);
    void (*onDoubleClick)(yeelight_dimmer_t *dimmer);
    void (*onMultipleClicks)(yeelight_dimmer_t *dimmer, char count);
    void (*onLongPress)(yeelight_dimmer_t *dimmer, char count);
} yeelight_dimmers_ctx;

typedef struct yeelight_report {
    uint16_t type;
    uint8_t length;
    uint8_t value1;
    uint8_t value2;
    uint8_t state;
} yeelight_report_t;

void yeelight_dimmers_init(yeelight_dimmers_ctx *ctx);
void yeelight_dimmers_add(yeelight_dimmers_ctx *ctx, char *mac, char *beacon_key, void *userdata);
void yeelight_dimmers_destroy(yeelight_dimmers_ctx *ctx);
void yellight_dimmer_check(yeelight_dimmers_ctx *ctx, uint8_t *data, uint32_t len);
void yeelight_dimmer_handle_advdata(yeelight_dimmers_ctx *ctx, yeelight_dimmer_t *dimmer, uint8_t *data, uint32_t len);
