# WiFi BlueTeaming Pet

A tiny ESP8266 robot pet with a 0.96" OLED that watches the WiFi around you for attacks, by **Gamkers**.
It is fully **passive**: it only listens to WiFi traffic and never transmits.

## Flash from your browser

**https://gamkers.github.io/WIFI_BlueTeaming/**

Open it in **Chrome or Edge on a computer**, plug in the board with a USB data cable, pick a version and click **Install**.
If no serial port shows up, install the CH340 or CP2102 USB driver for your board.

Prefer a tool? The `.bin` files are in [`firmware/`](firmware). Flash them at offset `0x0`, for example:

```bash
esptool.py --chip esp8266 --baud 460800 write_flash 0x0 firmware/esp8266_deauth_detector_buttons.bin
```

## Versions

| Version | Folder | What it does |
|---|---|---|
| **Buttons + Settings** (recommended) | [`esp8266_deauth_detector_buttons`](esp8266_deauth_detector_buttons) | All detections, a settings menu to switch each one on/off (saved), sensitivity, channel lock, and the optional **pet mode** |
| **Full** | [`esp8266_deauth_detector`](esp8266_deauth_detector) | All detections, no buttons needed |
| **Lite** | [`esp8266_deauth_detector_lite`](esp8266_deauth_detector_lite) | Deauth detection only |

### Detections (Full and Buttons versions)

- Deauth / disassociation attacks, with attacker, target and router MAC
- Evil twin (same WiFi name, different MAC) and combo attack (deauth + evil twin)
- Password capture attempt (handshake right after a deauth)
- Auth / association flood, karma / WiFi Pineapple, beacon flood
- Pwnagotchi and hack tool signatures
- Hidden WiFi camera finder
- Drone detector (WiFi Remote ID, DJI, drone WiFi names)
- Popups for phones probing for networks and for open WiFi
- Hunt mode: a signal meter (and LED brightness) to walk towards the device
- Screen saver against OLED burn-in

### Pet mode (Buttons version)

The classic radar UI is the default. Turn on **Settings → Pet face** and the radar becomes a robot face:

- Eyes look around while scanning, glance at new devices and look down at popups
- A reaction animation for every attack, before the usual alert screens:

| Attack | Pet reaction |
|---|---|
| Deauth | Shocked, then furious shaking eyes with lightning |
| Combo | Furious eyes with devil horns and a strobe |
| Evil twin | The face splits in two, the copy grows horns |
| Password capture | Wide eyes, sweat drop, a key floating away |
| Auth flood | Dizzy eyes while fake devices swarm in |
| Beacon flood | Eyes darting under raining WiFi signs |
| Karma / Pineapple | Suspicious squint with question marks |
| Hack tool / Pwnagotchi | Glaring at a bubble showing the tool |
| Hidden camera | Searching squint, focus brackets, REC |
| Drone | Eyes follow a drone across the sky |
| Attack ended | Happy bouncing eyes with sparkles |

- Mini eyes in the alert headers, a sleeping-face screen saver, and eyes in hunt mode that grow as you get closer

Both looks show a second page on every alert: a deauth analysis (reason code, spoofed MAC, peak rate, risk) or advice on what to do, with a risk rating.

## Pinout

| Part | Part pin | NodeMCU / D1 mini | GPIO | Versions |
|---|---|---|---|---|
| OLED SSD1306 128x64 I2C | VCC | `3V3` | - | All |
| | GND | `GND` | - | All |
| | SDA | `D1` | GPIO5 | All |
| | SCL / SCK | `D2` | GPIO4 | All |
| Button UP | pin ↔ GND | `D5` | GPIO14 | Buttons |
| Button OK | pin ↔ GND | `D6` | GPIO12 | Buttons |
| Button DOWN | pin ↔ GND | `D7` | GPIO13 | Buttons |
| Status LED | built-in | `D4` | GPIO2 | All |

- Buttons use the internal pull-ups, so no resistors are needed.
- OLED I2C address `0x3C`.

```
        NodeMCU / D1 mini                 OLED 0.96"
       ┌─────────────────┐              ┌───────────┐
       │ 3V3 ────────────┼──────────────┤ VCC       │
       │ GND ────────────┼──────────────┤ GND       │
       │ D1  (GPIO5) ────┼──────────────┤ SDA       │
       │ D2  (GPIO4) ────┼──────────────┤ SCL       │
       │                 │              └───────────┘
       │ D5  (GPIO14) ───┼──[ UP ]───┐
       │ D6  (GPIO12) ───┼──[ OK ]───┤   (Buttons version only)
       │ D7  (GPIO13) ───┼──[DOWN]───┤
       │ GND ────────────┼───────────┘
       └─────────────────┘
```

## Buttons version controls

| Screen | OK (D6) | UP / DOWN (D5 / D7) |
|---|---|---|
| Radar | Open settings | Fix channel 1–13 / AUTO hop |
| Settings | Switch on/off, Save & exit | Move (hold to scroll) |
| Alerts | Skip / dismiss | - |
| Hunt mode | Stop hunting | - |
| Screen saver | Any button wakes it | |

## Building from source

- Arduino IDE with the **ESP8266 core** (3.1.x), board **NodeMCU 1.0 (ESP-12E Module)** or **LOLIN(WEMOS) D1 mini**
- Libraries: **Adafruit SSD1306** and **Adafruit GFX**
- Open the `.ino` in the folder of the version you want and upload.

## Limits

- 2.4 GHz WiFi only (the ESP8266 can't hear 5 GHz).
- While locked on an attacked channel, other channels aren't watched.
- Mesh WiFi, busy places and your own cameras can cause false alarms.
- Drones that broadcast Remote ID over Bluetooth only, and Bluetooth trackers, can't be seen (needs an ESP32).

## Legal

For defensive use and learning, on networks you own or are allowed to monitor.

## License

[MIT](LICENSE) © Gamkers
