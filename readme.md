# ESP32 Yeelight YLKG07YL/YLKG08YL dimmer support component

## About

This is the component for Espressif's official IoT Development Framework for the ESP32 (ESP-IDF).
It gives you the ability to control your ESP32 based device with yeelight dimmer.

`yeelight_dimmer` - ESP-IDF component.
`demo` - demo project

Just implement handlers for dimmer events and register the dimmers. Check out the `demo`

## Details

Declare some event handlers
```
void onRotate(yeelight_dimmer_t *dimmer, signed char rotation, char state) {
}

void onClick(yeelight_dimmer_t *dimmer) {
}

```


Initialize the component context
```
yeelight_dimmers_ctx ctx;

yeelight_dimmers_init(&ctx);
ctx.onRotate = onRotate;
ctx.onClick = onClick;

yeelight_dimmers_add(&ctx, "\xF8\x24\x41\xC5\xA0\xBE", "\xA3\x15\x7D\xDF\xAC\x2A\x30\xA7\xF5\xE3\x38\x54", NULL);
```

Now, call `yellight_dimmer_check(&ctx, data, len);` at every received bluetooth advertising packet. It will check, parse, decrypt the packet data and call the corresponding event handlers.

The last argument of yeelight_dimmers_add() function is `userdata`. You can pass a pointer to some descriptor structure, title or even int variable here and access this pointer in event handler:

```
void onRotate(yeelight_dimmer_t *dimmer, signed char rotation, char state) {
	int *value = (int *)dimmer->userdata;
	*value += rotation;
	printf("value: %i\n", *value);
}
<...>
int app_main() {
	int val = 0;
	<...>
	yeelight_dimmers_add(&ctx, "\xF8\x24\x41\xC5\xA0\xBE", "\xA3\x15\x7D\xDF\xAC\x2A\x30\xA7\xF5\xE3\x38\x54", &val);
}
```


## MAC & beacon_key
Run the following to find out your dimmer MAC:
```
# hcitool lescan
LE Scan ...
F8:24:41:C5:A0:BE yee-rc
```

Check out https://github.com/psylity/yeelight-dimmer-python to retrieve your dimmer's beacon_key.
