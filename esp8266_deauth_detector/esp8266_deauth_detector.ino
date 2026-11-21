/*
  ============================================================
   ESP8266 Deauth Detector  -  passive WiFi attack monitor
  ============================================================
  Listens (receive only, never transmits) for WiFi deauthentication /
  disassociation frames, the frames used by "deauth" attacks that kick
  devices off a network. When a flood is seen it raises an alert and shows
  the MAC addresses involved.

  Board   : ESP8266 (NodeMCU 1.0 / LOLIN(WEMOS) D1 mini)
  Display : 0.96" SSD1306 OLED 128x64, I2C (0x3C)
  Wiring  : OLED SDA -> D1, SCL -> D2   (nothing else needed)
  Library : Adafruit SSD1306 + Adafruit GFX

  No buttons needed. The radar runs all the time and the screen jumps to
  the alert as soon as an attack is detected.
  Built-in LED (D4): a quick flash for each deauth frame, fast blinking during an attack.
*/

#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <ESP8266WiFi.h>
extern "C" {
#include "user_interface.h"
}

#ifndef ESP8266
#error "Select an ESP8266 board (NodeMCU 1.0 or LOLIN(WEMOS) D1 mini)"
#endif

// ================== HARDWARE ==================
#define OLED_ADDR 0x3C
#define PIN_SDA   5     // D1
#define PIN_SCL   4     // D2
#define LED_PIN   2     // D4  built-in LED (LOW = on)

#define WH SSD1306_WHITE
#define BK SSD1306_BLACK
#define INV SSD1306_INVERSE

Adafruit_SSD1306 oled(128, 64, &Wire, -1);

// ================== SETTINGS ==================
// Deauth frames per second that count as an attack.
// 3 = very sensitive (may react to normal disconnects), 10 = balanced, 30 = only big floods
#define ATTACK_RATE    10
#define CH_MAX         13
#define HOP_MS         250      // time on each channel while scanning
#define ATTACK_END_MS  6000     // attack is over after this long without frames
#define ATTACKER_MS    3000     // time per attacker on the alert screen
#define BOOT_MS        3200     // loading screen length
#define FRAME_MS       33
#define TWIN_ALERT_MS  9000     // how long the evil twin alert stays on screen
#define TWIN_GONE_MS   15000    // twin is "gone" once one of its copies is silent this long
// 1 = ignore twins whose two MACs come from the same maker (mesh WiFi / extenders
//     often share one network name). 0 = report every same-name, different-MAC pair.
#define TWIN_IGNORE_SAME_VENDOR 0
#define THREAT_ALERT_MS 9000    // karma / beacon flood / auth flood alert time
#define AUTH_RATE      25       // auth/association requests per second = flood
#define KARMA_NAMES    3        // one MAC using this many different WiFi names = karma
#define FLOOD_NEW      20       // this many brand-new networks within 10 s = beacon flood
#define FLOOD_GRACE_MS 40000    // ignore beacon floods right after power-on (first discovery)
#define PROBE_SHOW_MS  2500     // how long each "phone is looking for..." banner shows
#define DEAUTH_HOLD_MS 8000     // stay on a channel this long after any deauth (to catch the handshake)
#define CAPTURE_MSGS   2        // handshake messages after a deauth = password capture attempt
#define HUNT_AFTER_MS  10000    // deauth alert shows this long, then hunt mode starts
#define HUNT_MAX_MS    120000   // stop hunting an evil twin / karma device after 2 minutes
#define CAM_SCORE      40       // ESP32-type device streaming this much = possible spy camera
#define SAVER_MS       180000   // screen saver after 3 minutes without alerts (0 = never)

// ================== TYPES ==================
enum AppState : uint8_t { ST_BOOT, ST_SCAN, ST_ALERT, ST_ENDED, ST_TWIN, ST_TWINGONE, ST_THREAT, ST_HUNT };

struct DeauthEvt { uint8_t src[6], dst[6], bss[6]; uint16_t reason; int8_t rssi; uint8_t ch, type; };
struct MacEvt { uint8_t mac[6]; int8_t rssi; };

struct Attacker {
  bool used;
  uint8_t src[6], dst[6], bss[6];
  uint8_t ch;
  int8_t rssi;
  uint16_t reason;
  uint32_t count, prevCount, rate, first, last;
};

struct Contact { bool used, evil; uint8_t mac[6]; int8_t rssi; uint32_t last; };
// networks seen (from beacons) and evil twin pairs
struct Net { bool used; char ssid[33]; uint8_t bssid[6]; uint8_t ch; int8_t rssi; bool open; uint32_t last; };
struct Twin { bool used, shown, active; char ssid[33]; uint8_t a[6], b[6]; uint32_t first, last; };

struct ProbeEvt { uint8_t mac[6]; char ssid[33]; int8_t rssi; };
struct AuthEvt { uint8_t src[6], bss[6]; uint8_t ch, type; int8_t rssi; };
struct EapolEvt { uint8_t bss[6], cli[6]; uint8_t ch; };
enum HuntType : uint8_t { H_NONE, H_DEAUTH, H_AUTH, H_TWIN, H_KARMA, H_TOOL, H_CAM, H_DRONE };
struct KarmaTrack { bool used; uint8_t mac[6]; uint32_t hashes[8]; uint8_t n; char names[3][17]; uint32_t last; int8_t rssi; uint8_t ch; };
struct Seen { uint32_t h, t; };
struct Banner { char ssid[17]; uint8_t mac[6]; uint8_t type, ch; };   // type 0 = probe, 1 = open WiFi
enum ThreatType : uint8_t { TH_CAPTURE, TH_AUTH, TH_KARMA, TH_TOOL, TH_CAM, TH_DRONE, TH_FLOOD, TH_COUNT };
struct Threat { bool active, alerted; uint32_t start, lastHot; };

// ================== SNIFFER (runs inside the WiFi driver) ==================
volatile uint32_t pktCount = 0, deauthRaw = 0;
volatile uint8_t curCh = 1;
DeauthEvt evQ[16];
volatile uint8_t evHead = 0, evTail = 0;
MacEvt macQ[16];
volatile uint8_t mqHead = 0, mqTail = 0;

struct BeaconEvt { uint8_t bssid[6]; char ssid[33]; uint8_t ch; int8_t rssi; bool open; uint8_t flags; char extra[21]; };
// flags: 1 = Pwnagotchi, 2 = drone Remote ID, 4 = DJI drone
struct DataEvt { uint8_t mac[6]; int8_t rssi; uint8_t ch; };
struct CamTrack { bool used; uint8_t mac[6]; uint16_t win; float score; int8_t rssi; uint8_t ch; uint32_t last; };
BeaconEvt bcQ[16];
volatile uint8_t bqHead = 0, bqTail = 0;
ProbeEvt prQ[8];
volatile uint8_t pqHead = 0, pqTail = 0;
AuthEvt auQ[16];
volatile uint8_t aqHead = 0, aqTail = 0;
volatile uint32_t authRaw = 0;
EapolEvt eaQ[8];
volatile uint8_t eqHead = 0, eqTail = 0;
volatile uint32_t eapolRaw = 0;
DataEvt dataQ[16];
volatile uint8_t dqHead = 0, dqTail = 0;

void sniffer(uint8_t *buf, uint16_t len) {
  if (!buf || len < 12 + 24) return;
  pktCount++;
  uint8_t *f = buf + 12;               // 802.11 header starts after the 12-byte RxControl
  uint8_t fc = f[0];
  int8_t rssi = (int8_t)buf[0];
  if (fc == 0xC0 || fc == 0xA0) {      // deauthentication / disassociation
    deauthRaw++;
    uint8_t nh = (evHead + 1) & 15;
    if (nh != evTail) {
      DeauthEvt &e = evQ[evHead];
      memcpy(e.dst, f + 4, 6);
      memcpy(e.src, f + 10, 6);
      memcpy(e.bss, f + 16, 6);
      e.reason = (len >= 12 + 26) ? (f[24] | (f[25] << 8)) : 0;
      e.rssi = rssi;
      e.ch = curCh;
      e.type = (fc == 0xC0) ? 0 : 1;
      evHead = nh;
    }
  } else if (fc == 0x40) {                                       // probe request (a phone looking for WiFi)
    uint8_t sl = f[25];
    if (f[24] == 0 && sl <= 32) {
      uint8_t nh = (pqHead + 1) & 7;
      if (nh != pqTail) {
        ProbeEvt &p = prQ[pqHead];
        memcpy(p.mac, f + 10, 6);
        memcpy(p.ssid, f + 26, sl);
        p.ssid[sl] = 0;
        p.rssi = rssi;
        pqHead = nh;
      }
    }
  } else if (fc == 0xB0 || fc == 0x00 || fc == 0x20) {           // authentication / (re)association request
    authRaw++;
    uint8_t nh = (aqHead + 1) & 15;
    if (nh != aqTail) {
      AuthEvt &a = auQ[aqHead];
      memcpy(a.src, f + 10, 6);
      memcpy(a.bss, f + 16, 6);
      a.ch = curCh;
      a.type = fc == 0xB0 ? 0 : 1;
      a.rssi = rssi;
      aqHead = nh;
    }
  } else if ((fc == 0x80 || fc == 0x50) && len >= 12 + 40) {   // beacon / probe response
    uint8_t sl = f[37];
    if (f[36] == 0 && sl <= 32) {
      bool hidden = sl == 0 || f[38] == 0;
      uint8_t flags = 0;
      static const uint8_t PWN[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD};
      if (memcmp(f + 16, PWN, 6) == 0) flags |= 1;              // Pwnagotchi's fixed MAC
      uint8_t ch = curCh;
      int q = 38 + sl;
      for (; q + 2 < 112; q += 2 + f[q + 1]) {                  // walk the tags
        uint8_t tg = f[q], tl = f[q + 1];
        if (tg == 3 && tl == 1) ch = f[q + 2];
        if (tg == 221 && tl >= 4 && q + 5 < 112) {
          if (f[q + 2] == 0xFA && f[q + 3] == 0x0B && f[q + 4] == 0xBC && f[q + 5] == 0x0D) flags |= 2;   // ASTM Remote ID
          if (f[q + 2] == 0x26 && f[q + 3] == 0x37 && f[q + 4] == 0x12) flags |= 4;                       // DJI DroneID
        }
      }
      if (!hidden || flags) {
        uint8_t nh = (bqHead + 1) & 15;
        if (nh != bqTail) {
          BeaconEvt &b = bcQ[bqHead];
          memcpy(b.bssid, f + 16, 6);
          if (hidden) sl = 0;
          memcpy(b.ssid, f + 38, sl);
          b.ssid[sl] = 0;
          b.rssi = rssi;
          b.open = !(f[34] & 0x10);                               // privacy bit in capability info
          b.ch = ch;
          b.flags = flags;
          b.extra[0] = 0;
          if (flags & 1) {                                        // Pwnagotchi: pull "name":"..." out of its JSON
            for (int i = 38 + sl; i + 8 < 112; i++)
              if (memcmp(f + i, "name\":\"", 7) == 0) {
                int j = 0;
                for (i += 7; i < 112 && f[i] != '"' && j < 20; i++) b.extra[j++] = f[i];
                b.extra[j] = 0;
                break;
              }
          }
          if (flags & 2) {                                        // Remote ID: serial number from the Basic ID message
            for (int i = 38 + sl; i + 25 < 112; i++)
              if (f[i] == 0xFA && f[i + 1] == 0x0B && f[i + 2] == 0xBC && f[i + 3] == 0x0D) {
                int m = i + 5;                                    // after counter: message pack header
                if (m + 3 < 112 && (f[m] >> 4) == 0xF) m += 3;    // skip pack header
                if (m + 22 <= 112 && (f[m] >> 4) == 0x0) {        // Basic ID message
                  int j = 0;
                  for (int k = 0; k < 20 && f[m + 2 + k] >= 32 && f[m + 2 + k] < 127; k++) b.extra[j++] = f[m + 2 + k];
                  b.extra[j] = 0;
                }
                break;
              }
          }
          bqHead = nh;
        }
      }
    }
  } else {
    // WPA handshake (EAPOL): unencrypted data frame with LLC/SNAP type 0x888E
    if ((fc == 0x08 || fc == 0x88) && !(f[1] & 0x40) && (f[1] & 3) != 3 && len >= 12 + 34) {
      uint8_t h = fc == 0x88 ? 26 : 24;
      if (f[h] == 0xAA && f[h + 1] == 0xAA && f[h + 6] == 0x88 && f[h + 7] == 0x8E) {
        eapolRaw++;
        uint8_t nh = (eqHead + 1) & 7;
        if (nh != eqTail) {
          EapolEvt &e = eaQ[eqHead];
          uint8_t ds = f[1] & 3;
          const uint8_t *bss = ds == 1 ? f + 4 : (ds == 2 ? f + 10 : f + 16);
          const uint8_t *cli = ds == 2 ? f + 4 : f + 10;
          memcpy(e.bss, bss, 6);
          memcpy(e.cli, cli, 6);
          e.ch = curCh;
          eqHead = nh;
        }
        return;
      }
    }
    if ((fc & 0x0C) == 0x08 && (f[1] & 3) == 1 && (pktCount & 3) == 0) {   // device -> AP data, 1 in 4
      uint8_t nh = (dqHead + 1) & 15;
      if (nh != dqTail) { memcpy(dataQ[dqHead].mac, f + 10, 6); dataQ[dqHead].rssi = rssi; dataQ[dqHead].ch = curCh; dqHead = nh; }
    }
    if ((pktCount & 7) == 0) {          // sample normal traffic for the radar
      uint8_t nh = (mqHead + 1) & 15;
      if (nh != mqTail) {
        memcpy(macQ[mqHead].mac, f + 10, 6);
        macQ[mqHead].rssi = rssi;
        mqHead = nh;
      }
    }
  }
}

// ================== GLOBALS ==================
AppState state = ST_BOOT;
uint32_t stateStart = 0, lastFrame = 0;

bool locked = false;
uint32_t lastHop = 0, hopPkt = 0, hopDeauth = 0;
uint32_t lastSec = 0, secPkt = 0, secDeauth = 0;
uint32_t pktRate = 0, deauthRate = 0;
uint16_t chLevel[CH_MAX + 1], chPeak[CH_MAX + 1], deauthChSec[CH_MAX + 1];
uint32_t chDeauthAt[CH_MAX + 1];

Attacker att[8];
Contact ct[20];

// networks seen (from beacons) and evil twin pairs
Net nets[24];
Twin twins[4];
int twinSel = -1;

// karma / beacon flood / auth flood
Threat th[TH_COUNT];
int thSel = 0;
KarmaTrack kt[8];
int karmaSel = 0;
Seen seenB[128];                     // networks already known (beacon flood check)
uint16_t newPerSec[10], newNetSec = 0, floodCount = 0;
char floodNames[3][17];
uint8_t floodNameIdx = 0;
uint32_t hopAuth = 0, secAuth = 0, authRate = 0, authEst = 0;
Seen authSrc[32];                    // different "devices" sending auth requests
uint8_t authBss[6];
uint8_t authCh = 0, authType = 0;

// probe requests: phones nearby and the networks they look for
Seen probeSeen[48], ssidShown[16], probers[32];
Banner banners[8];
Seen openSeen[32], openNames[16];   // open networks already announced
uint8_t bnHead = 0, bnTail = 0;
Banner curBanner;
bool bannerOn = false;

// password capture (handshake after deauth)
uint32_t lastDeauthAt = 0, holdUntil = 0;
uint8_t capBss[6], capCli[6];
uint8_t capCh = 0;
uint16_t capMsgs = 0;
uint32_t capLast = 0, capDeauthAgo = 0;

// hunt mode
uint8_t huntType = H_NONE;
uint8_t huntMac[6];
float huntRssi = -100;
int8_t huntPeak = -127;
uint32_t huntLastFrame = 0, huntGoneAt = 0;

// hack tools / cameras / drones
struct { uint8_t mac[6]; char name[21]; char ssid[17]; uint8_t ch; int8_t rssi; bool pwn; } tool;
struct { uint8_t mac[6]; char brand[13]; char reason[18]; uint8_t ch; int8_t rssi; } cam;
struct { uint8_t mac[6]; char ssid[17]; char id[21]; char kind[12]; uint8_t ch; int8_t rssi; } drone;
CamTrack camT[12];
Seen toolSeen[8];

// screen saver
uint32_t lastActivity = 0;
bool dimmed = false;
uint32_t bannerStart = 0;

// combo attack: deauth flood while an evil twin is up (kick people off the real AP so they join the fake one)
int comboTwin = -1;
uint8_t comboReal[6], comboFake[6];
bool comboKnown = false, lastWasCombo = false;

bool attack = false;
uint32_t attackStart = 0, lastHot = 0, attackStartPkts = 0;
uint32_t endDur = 0, endPkts = 0;
uint32_t ledFlashUntil = 0, ledSeenDeauth = 0;

// ================== UTILS ==================
inline int imin(int a, int b) { return a < b ? a : b; }
inline int imax(int a, int b) { return a > b ? a : b; }
inline float clamp01(float p) { return p < 0 ? 0 : (p > 1 ? 1 : p); }
inline float ease(float p) { p = clamp01(p); return (1 - cosf(p * PI)) / 2; }

uint32_t macHash(const uint8_t *m) {
  uint32_t h = 2166136261UL;
  for (int i = 0; i < 6; i++) { h ^= m[i]; h *= 16777619UL; }
  return h;
}
bool macEq(const uint8_t *a, const uint8_t *b) { return memcmp(a, b, 6) == 0; }
bool isBroadcast(const uint8_t *m) { for (int i = 0; i < 6; i++) if (m[i] != 0xFF) return false; return true; }
void fmtMac(char *b, const uint8_t *m) {
  sprintf(b, "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
}

bool frameDue() {
  uint32_t now = millis();
  if (now - lastFrame < FRAME_MS) return false;
  lastFrame = now;
  return true;
}

void txt(int x, int y, const char *s, uint8_t sz, uint16_t c) {
  oled.setTextSize(sz); oled.setTextColor(c); oled.setCursor(x, y); oled.print(s);
}
void txtC(int y, const char *s, uint8_t sz, uint16_t c) { txt((128 - (int)strlen(s) * 6 * sz) / 2, y, s, sz, c); }

void shiftPage(uint8_t p, int k) {
  uint8_t *row = oled.getBuffer() + p * 128;
  if (k > 0) { memmove(row + k, row, 128 - k); memset(row, 0, k); }
  else if (k < 0) { k = -k; memmove(row, row + k, 128 - k); memset(row + 128 - k, 0, k); }
}

// ================== RADIO ==================
void hopTo(uint8_t ch) { curCh = ch; wifi_set_channel(ch); }

void startSniffer() {
  wifi_set_opmode(STATION_MODE);
  wifi_station_disconnect();
  wifi_promiscuous_enable(0);
  wifi_set_promiscuous_rx_cb(sniffer);
  wifi_promiscuous_enable(1);
  hopTo(1);
}

// ================== TRACKING ==================
void addAttacker(const DeauthEvt &e, uint32_t now) {
  int slot = -1, freeSlot = -1, oldest = 0;
  for (int i = 0; i < 8; i++) {
    if (att[i].used && macEq(att[i].src, e.src) && macEq(att[i].bss, e.bss)) { slot = i; break; }
    if (!att[i].used && freeSlot < 0) freeSlot = i;
    if (att[i].used && att[i].last < att[oldest].last) oldest = i;
  }
  Attacker *a;
  if (slot >= 0) a = &att[slot];
  else {
    a = &att[freeSlot >= 0 ? freeSlot : oldest];
    memset(a, 0, sizeof(Attacker));
    a->used = true;
    memcpy(a->src, e.src, 6);
    memcpy(a->bss, e.bss, 6);
    a->first = now;
  }
  memcpy(a->dst, e.dst, 6);
  a->ch = e.ch;
  a->rssi = e.rssi;
  a->reason = e.reason;
  a->count++;
  a->last = now;
  for (int i = 0; i < 20; i++) if (ct[i].used && macEq(ct[i].mac, e.src)) ct[i].evil = true;
}

void addContact(const MacEvt &m, uint32_t now) {
  if (m.mac[0] & 0x01) return;                  // skip multicast/broadcast sources
  int slot = -1, freeSlot = -1, oldest = 0;
  for (int i = 0; i < 20; i++) {
    if (ct[i].used && macEq(ct[i].mac, m.mac)) { slot = i; break; }
    if (!ct[i].used && freeSlot < 0) freeSlot = i;
    if (ct[i].used && ct[i].last < ct[oldest].last) oldest = i;
  }
  if (slot < 0) slot = freeSlot >= 0 ? freeSlot : oldest;
  Contact &c = ct[slot];
  if (!c.used || !macEq(c.mac, m.mac)) { c.used = true; c.evil = false; memcpy(c.mac, m.mac, 6); }
  c.rssi = m.rssi;
  c.last = now;
}

Net *findNet(const uint8_t *bssid) {
  for (int i = 0; i < 24; i++) if (nets[i].used && macEq(nets[i].bssid, bssid)) return &nets[i];
  return nullptr;
}

void registerTwin(const char *ssid, const uint8_t *a, const uint8_t *b, uint32_t now) {
  int freeSlot = -1, oldest = 0;
  for (int i = 0; i < 4; i++) {
    Twin &t = twins[i];
    if (t.used && strcmp(t.ssid, ssid) == 0 &&
        ((macEq(t.a, a) && macEq(t.b, b)) || (macEq(t.a, b) && macEq(t.b, a)))) { t.last = now; return; }
    if (!t.used && freeSlot < 0) freeSlot = i;
    if (t.used && twins[i].last < twins[oldest].last) oldest = i;
  }
  Twin &t = twins[freeSlot >= 0 ? freeSlot : oldest];
  t.used = true;
  t.shown = false;
  t.active = false;
  strcpy(t.ssid, ssid);
  memcpy(t.a, a, 6);
  memcpy(t.b, b, 6);
  t.first = t.last = now;
  char ma[18], mb[18];
  fmtMac(ma, a); fmtMac(mb, b);
  Serial.printf("[!] EVIL TWIN? \"%s\"  %s  vs  %s\n", ssid, ma, mb);
}

void updateNet(const BeaconEvt &e, uint32_t now) {
  Net *n = findNet(e.bssid);
  if (!n) {
    int freeSlot = -1, oldest = 0;
    for (int i = 0; i < 24; i++) {
      if (!nets[i].used && freeSlot < 0) freeSlot = i;
      if (nets[i].used && nets[i].last < nets[oldest].last) oldest = i;
    }
    n = &nets[freeSlot >= 0 ? freeSlot : oldest];
    n->used = true;
    memcpy(n->bssid, e.bssid, 6);
  }
  strcpy(n->ssid, e.ssid);
  n->ch = e.ch;
  n->rssi = e.rssi;
  n->open = e.open;
  n->last = now;
  // same network name, different MAC  ->  possible evil twin
  for (int i = 0; i < 24; i++) {
    Net &o = nets[i];
    if (!o.used || &o == n || now - o.last > TWIN_GONE_MS) continue;
    if (strcmp(o.ssid, n->ssid) != 0) continue;
    if (TWIN_IGNORE_SAME_VENDOR && memcmp(o.bssid, n->bssid, 3) == 0) continue;
    registerTwin(n->ssid, o.bssid, n->bssid, now);
  }
}

// a twin is active only while BOTH copies are still broadcasting
bool twinActive(const Twin &t, uint32_t now) {
  if (!t.used) return false;
  Net *a = findNet(t.a), *b = findNet(t.b);
  return a && b && now - a->last < TWIN_GONE_MS && now - b->last < TWIN_GONE_MS;
}

uint32_t strHash(const char *s) {
  uint32_t h = 2166136261UL;
  while (*s) { h ^= (uint8_t)*s++; h *= 16777619UL; }
  return h;
}

// true if 'h' was seen within 'ttl'; always remembers it (refreshing the time)
bool seenRecently(Seen *arr, int n, uint32_t h, uint32_t now, uint32_t ttl) {
  int oldest = 0;
  for (int i = 0; i < n; i++) {
    if (arr[i].t && arr[i].h == h) { bool r = now - arr[i].t < ttl; arr[i].t = now; return r; }
    if (arr[i].t < arr[oldest].t) oldest = i;
  }
  arr[oldest].h = h;
  arr[oldest].t = now ? now : 1;
  return false;
}
int countRecent(Seen *arr, int n, uint32_t now, uint32_t ttl) {
  int c = 0;
  for (int i = 0; i < n; i++) if (arr[i].t && now - arr[i].t < ttl) c++;
  return c;
}

void threatHot(uint8_t type, uint32_t now) {
  Threat &t = th[type];
  t.lastHot = now;
  if (t.active) return;
  t.active = true;
  t.alerted = false;
  t.start = now;
  static const char *N[TH_COUNT] = {"PASSWORD CAPTURE ATTEMPT", "AUTH FLOOD", "KARMA", "HACK TOOL", "HIDDEN CAMERA", "DRONE", "BEACON FLOOD"};
  Serial.printf("[!] %s detected\n", N[type]);
}

void threatTick(uint32_t now) {
  static const uint32_t END_MS[TH_COUNT] = {30000, 8000, 60000, 60000, 60000, 30000, 15000};
  for (int i = 0; i < TH_COUNT; i++)
    if (th[i].active && now - th[i].lastHot > END_MS[i]) { th[i].active = false; Serial.printf("[+] threat %d ended\n", i); }
}

// karma: one MAC answering with many different network names
void karmaSeen(const BeaconEvt &e, uint32_t now) {
  int slot = -1, freeSlot = -1, oldest = 0;
  for (int i = 0; i < 8; i++) {
    if (kt[i].used && macEq(kt[i].mac, e.bssid)) { slot = i; break; }
    if (!kt[i].used && freeSlot < 0) freeSlot = i;
    if (kt[i].used && kt[i].last < kt[oldest].last) oldest = i;
  }
  if (slot < 0) {
    slot = freeSlot >= 0 ? freeSlot : oldest;
    memset(&kt[slot], 0, sizeof(KarmaTrack));
    kt[slot].used = true;
    memcpy(kt[slot].mac, e.bssid, 6);
  }
  KarmaTrack &k = kt[slot];
  if (now - k.last > 120000) k.n = 0;
  uint32_t h = strHash(e.ssid);
  bool found = false;
  for (int i = 0; i < k.n; i++) if (k.hashes[i] == h) found = true;
  if (!found && k.n < 8) {
    if (k.n < 3) { strncpy(k.names[k.n], e.ssid, 16); k.names[k.n][16] = 0; }
    k.hashes[k.n++] = h;
  }
  k.last = now;
  k.rssi = e.rssi;
  k.ch = e.ch;
  if (k.n >= KARMA_NAMES) { karmaSel = slot; threatHot(TH_KARMA, now); }
}

// beacon flood: lots of brand-new networks appearing at once
void floodSeen(const BeaconEvt &e, uint32_t now) {
  if (seenRecently(seenB, 128, macHash(e.bssid), now, 600000UL)) return;
  newNetSec++;
  strncpy(floodNames[floodNameIdx], e.ssid, 16);
  floodNames[floodNameIdx][16] = 0;
  floodNameIdx = (floodNameIdx + 1) % 3;
}

void pushBanner(uint8_t type, const char *ssid, const uint8_t *mac, uint8_t ch) {
  uint8_t nh = (bnHead + 1) & 7;
  if (nh == bnTail) return;                       // queue full: skip
  Banner &bn = banners[bnHead];
  strncpy(bn.ssid, ssid, 16);
  bn.ssid[16] = 0;
  for (char *c = bn.ssid; *c; c++) if (*c < 32 || *c > 126) *c = '?';
  memcpy(bn.mac, mac, 6);
  bn.type = type;
  bn.ch = ch;
  bnHead = nh;
}

// open (no password) network: announce once per network (30 min), same name max once per 5 min
void openSeenCheck(const BeaconEvt &e, uint32_t now) {
  if (!e.open) return;
  bool dupMac = seenRecently(openSeen, 32, macHash(e.bssid), now, 1800000UL);
  bool dupName = seenRecently(openNames, 16, strHash(e.ssid), now, 300000UL);
  if (dupMac || dupName) return;
  pushBanner(1, e.ssid, e.bssid, e.ch);
  char m[18];
  fmtMac(m, e.bssid);
  Serial.printf("[open] \"%s\" %s ch%u %ddBm\n", e.ssid, m, e.ch, e.rssi);
}

void handleProbe(const ProbeEvt &p, uint32_t now) {
  if (p.mac[0] & 0x01) return;
  seenRecently(probers, 32, macHash(p.mac), now, 60000);              // phones nearby
  if (!p.ssid[0]) return;                                              // "any network" probe: nothing to show
  // don't repeat: same phone + same name (30 min), or same name from any phone (5 min)
  bool dupPair = seenRecently(probeSeen, 48, macHash(p.mac) ^ strHash(p.ssid), now, 1800000UL);
  bool dupName = seenRecently(ssidShown, 16, strHash(p.ssid), now, 300000UL);
  if (dupPair || dupName) return;
  pushBanner(0, p.ssid, p.mac, 0);
  char m[18];
  fmtMac(m, p.mac);
  Serial.printf("[probe] %s looking for \"%s\"\n", m, p.ssid);
}

// ---- signature lists (lower case; add your own) ----
const char *TOOL_SIG[] = {"pwnagotchi", "pineapple", "pwned", "deauther", "marauder", "wifi duck", "o.mg",
                          "hak5", "evil portal", "evil-portal", "evilportal", "flipper", "airgeddon",
                          "wifiphisher", "fluxion", "nugget", "bettercap"};
const char *CAM_SSID[] = {"ipcam", "ipc-", "ipc_", "hik", "wificam", "esp32-cam", "esp32cam", "v380", "spycam",
                          "hdwificam", "lookcam", "camera", "cam_", "dvr", "wyze", "reolink", "dahua", "ezviz", "yoosee"};
const char *DRONE_SSID[] = {"dji", "tello", "mavic", "spark-", "anafi", "parrot", "skydio", "autel", "evo-",
                            "fimi", "holystone", "potensic", "wifi-uav", "wifi_uav", "drone", "jjrc", "ryze", "syma"};
struct Oui { uint8_t o[3]; const char *name; };
const Oui CAM_OUI[] = {
  {{0x44, 0x19, 0xB6}, "Hikvision"}, {{0xBC, 0xAD, 0x28}, "Hikvision"}, {{0xC0, 0x56, 0xE3}, "Hikvision"},
  {{0x3C, 0xEF, 0x8C}, "Dahua"}, {{0x90, 0x02, 0xA9}, "Dahua"}, {{0xE0, 0x50, 0x8B}, "Dahua"},
  {{0x2C, 0xAA, 0x8E}, "Wyze"}, {{0xD0, 0x3F, 0x27}, "Wyze"}, {{0xEC, 0x71, 0xDB}, "Reolink"},
  {{0x9C, 0x8E, 0xCD}, "Amcrest"}, {{0x34, 0x3E, 0xA4}, "Ring"},
};
const uint8_t ESP_OUI[][3] = {
  {0x24, 0x0A, 0xC4}, {0x30, 0xAE, 0xA4}, {0xA4, 0xCF, 0x12}, {0x84, 0xF3, 0xEB}, {0x5C, 0xCF, 0x7F},
  {0x60, 0x01, 0x94}, {0xBC, 0xDD, 0xC2}, {0x24, 0x6F, 0x28}, {0x7C, 0x9E, 0xBD}, {0x8C, 0xAA, 0xB5},
  {0xC4, 0x4F, 0x33}, {0xEC, 0xFA, 0xBC}, {0x3C, 0x71, 0xBF}, {0x98, 0xF4, 0xAB}, {0x10, 0x52, 0x1C},
  {0x94, 0xB9, 0x7E}, {0xAC, 0x67, 0xB2}, {0x48, 0x3F, 0xDA}, {0xE8, 0xDB, 0x84}, {0x58, 0xBF, 0x25},
};

bool containsCI(const char *hay, const char *needle) {     // case-insensitive "contains"
  size_t n = strlen(needle);
  for (; *hay; hay++) {
    size_t i = 0;
    while (i < n && hay[i] && tolower((uint8_t)hay[i]) == needle[i]) i++;
    if (i == n) return true;
  }
  return false;
}
const char *matchList(const char *ssid, const char **list, int n) {
  for (int i = 0; i < n; i++) if (containsCI(ssid, list[i])) return list[i];
  return nullptr;
}
const char *camBrand(const uint8_t *mac) {
  for (const Oui &o : CAM_OUI) if (memcmp(mac, o.o, 3) == 0) return o.name;
  return nullptr;
}
bool isEspressif(const uint8_t *mac) {
  for (auto &o : ESP_OUI) if (memcmp(mac, o, 3) == 0) return true;
  return false;
}

void reportTool(const BeaconEvt &e, const char *what, bool pwn, uint32_t now) {
  bool again = seenRecently(toolSeen, 8, macHash(e.bssid), now, 1800000UL);
  if (!again || !th[TH_TOOL].active) {
    memcpy(tool.mac, e.bssid, 6);
    strncpy(tool.name, what, 20); tool.name[20] = 0;
    strncpy(tool.ssid, e.ssid, 16); tool.ssid[16] = 0;
    tool.pwn = pwn;
    if (!again) Serial.printf("[!] %s: \"%s\"\n", pwn ? "PWNAGOTCHI" : "HACK TOOL", what);
  }
  if (macEq(tool.mac, e.bssid)) { tool.ch = e.ch; tool.rssi = e.rssi; }
  threatHot(TH_TOOL, now);
}

void reportCam(const uint8_t *mac, const char *brand, const char *reason, int8_t rssi, uint8_t ch, uint32_t now) {
  if (!th[TH_CAM].active || macEq(cam.mac, mac)) {
    if (!th[TH_CAM].active) Serial.printf("[!] HIDDEN CAMERA? %s (%s)\n", brand, reason);
    memcpy(cam.mac, mac, 6);
    strncpy(cam.brand, brand, 12); cam.brand[12] = 0;
    strncpy(cam.reason, reason, 17); cam.reason[17] = 0;
    cam.rssi = rssi;
    cam.ch = ch;
    threatHot(TH_CAM, now);
  }
}

void reportDrone(const BeaconEvt &e, const char *kind, uint32_t now) {
  if (!th[TH_DRONE].active || macEq(drone.mac, e.bssid)) {
    if (!th[TH_DRONE].active) Serial.printf("[!] DRONE: %s \"%s\" %s\n", kind, e.ssid, e.extra);
    memcpy(drone.mac, e.bssid, 6);
    strncpy(drone.ssid, e.ssid, 16); drone.ssid[16] = 0;
    if (e.extra[0]) { strncpy(drone.id, e.extra, 20); drone.id[20] = 0; }
    else if (!th[TH_DRONE].active) drone.id[0] = 0;
    strncpy(drone.kind, kind, 11); drone.kind[11] = 0;
    drone.rssi = e.rssi;
    drone.ch = e.ch;
    threatHot(TH_DRONE, now);
  }
}

// look at every beacon for tools, cameras and drones
void signatureCheck(const BeaconEvt &e, uint32_t now) {
  const char *m;
  if (e.flags & 1) reportTool(e, e.extra[0] ? e.extra : "Pwnagotchi", true, now);
  else if (e.ssid[0] && (m = matchList(e.ssid, TOOL_SIG, sizeof(TOOL_SIG) / sizeof(TOOL_SIG[0])))) reportTool(e, e.ssid, false, now);
  else if (e.bssid[0] == 0x00 && e.bssid[1] == 0x13 && e.bssid[2] == 0x37) reportTool(e, "WiFi Pineapple", false, now);

  if (e.flags & 2) reportDrone(e, "Remote ID", now);
  else if (e.flags & 4) reportDrone(e, "DJI", now);
  else if (e.ssid[0] && matchList(e.ssid, DRONE_SSID, sizeof(DRONE_SSID) / sizeof(DRONE_SSID[0]))) reportDrone(e, "WiFi name", now);

  const char *b = camBrand(e.bssid);
  if (b) reportCam(e.bssid, b, "maker ID", e.rssi, e.ch, now);
  else if (e.ssid[0] && (m = matchList(e.ssid, CAM_SSID, sizeof(CAM_SSID) / sizeof(CAM_SSID[0])))) reportCam(e.bssid, e.ssid, "camera WiFi name", e.rssi, e.ch, now);
}

// devices uploading data: known camera makers, or ESP32-type boards streaming a lot (spy cams)
void handleData(const DataEvt &d, uint32_t now) {
  if (d.mac[0] & 0x01) return;
  if ((huntType == H_CAM) && macEq(d.mac, huntMac)) huntFeed(d.rssi, now);
  const char *b = camBrand(d.mac);
  bool esp = !b && isEspressif(d.mac);
  if (!b && !esp) return;
  int slot = -1, freeSlot = -1, oldest = 0;
  for (int i = 0; i < 12; i++) {
    if (camT[i].used && macEq(camT[i].mac, d.mac)) { slot = i; break; }
    if (!camT[i].used && freeSlot < 0) freeSlot = i;
    if (camT[i].used && camT[i].last < camT[oldest].last) oldest = i;
  }
  if (slot < 0) {
    slot = freeSlot >= 0 ? freeSlot : oldest;
    memset(&camT[slot], 0, sizeof(CamTrack));
    camT[slot].used = true;
    memcpy(camT[slot].mac, d.mac, 6);
  }
  CamTrack &c = camT[slot];
  c.win++;
  c.rssi = d.rssi;
  c.ch = d.ch;
  c.last = now;
  if (b) reportCam(d.mac, b, "camera uploading", d.rssi, d.ch, now);
  else if (c.score >= CAM_SCORE) reportCam(d.mac, "ESP32 device", "streaming video?", d.rssi, d.ch, now);
}

void camTick(uint32_t now) {        // once per second: ~30 s running total of upload samples
  for (int i = 0; i < 12; i++) {
    if (!camT[i].used) continue;
    camT[i].score = camT[i].score * 29.0f / 30.0f + camT[i].win;
    camT[i].win = 0;
    if (now - camT[i].last > 120000) camT[i].used = false;
  }
}

void huntFeed(int8_t rssi, uint32_t now) {
  huntRssi = (huntRssi < -99) ? rssi : huntRssi * 0.7f + rssi * 0.3f;   // smooth the signal
  if (rssi > huntPeak) huntPeak = rssi;
  huntLastFrame = now;
}

void handleEapol(const EapolEvt &e, uint32_t now) {
  if (!macEq(e.bss, capBss) || now - capLast > 20000) {   // new handshake
    memcpy(capBss, e.bss, 6);
    memcpy(capCli, e.cli, 6);
    capMsgs = 0;
  }
  capMsgs++;
  capLast = now;
  capCh = e.ch;
  bool deauthBefore = attack || (lastDeauthAt && now - lastDeauthAt < 30000);
  if (capMsgs >= CAPTURE_MSGS && deauthBefore) {
    capDeauthAgo = now - lastDeauthAt;
    threatHot(TH_CAPTURE, now);
  }
}

void handleAuth(const AuthEvt &a, uint32_t now) {
  if (huntType == H_AUTH) huntFeed(a.rssi, now);
  seenRecently(authSrc, 32, macHash(a.src), now, 5000);
  memcpy(authBss, a.bss, 6);
  authCh = a.ch;
  authType = a.type;
}

void drainQueues(uint32_t now) {
  while (pqTail != pqHead) {
    ProbeEvt p = prQ[pqTail];
    pqTail = (pqTail + 1) & 7;
    handleProbe(p, now);
  }
  while (aqTail != aqHead) {
    AuthEvt a = auQ[aqTail];
    aqTail = (aqTail + 1) & 15;
    handleAuth(a, now);
  }
  while (dqTail != dqHead) {
    DataEvt d = dataQ[dqTail];
    dqTail = (dqTail + 1) & 15;
    handleData(d, now);
  }
  while (eqTail != eqHead) {
    EapolEvt e = eaQ[eqTail];
    eqTail = (eqTail + 1) & 7;
    handleEapol(e, now);
  }
  while (bqTail != bqHead) {
    BeaconEvt e = bcQ[bqTail];
    bqTail = (bqTail + 1) & 15;
    if ((huntType == H_TWIN || huntType == H_KARMA || huntType == H_TOOL || huntType == H_CAM || huntType == H_DRONE)
        && macEq(e.bssid, huntMac)) huntFeed(e.rssi, now);
    signatureCheck(e, now);
    if (!e.ssid[0]) continue;                       // hidden network: only used for the checks above
    updateNet(e, now);
    karmaSeen(e, now);
    floodSeen(e, now);
    openSeenCheck(e, now);
  }
  while (evTail != evHead) {
    DeauthEvt e = evQ[evTail];
    evTail = (evTail + 1) & 15;
    addAttacker(e, now);
    lastDeauthAt = now;
    if (huntType == H_DEAUTH) huntFeed(e.rssi, now);
    if (e.ch >= 1 && e.ch <= CH_MAX) { deauthChSec[e.ch]++; chDeauthAt[e.ch] = now; }
  }
  while (mqTail != mqHead) {
    MacEvt m = macQ[mqTail];
    mqTail = (mqTail + 1) & 15;
    addContact(m, now);
  }
}

// attackers seen in the last few seconds, busiest first
int activeAttackers(int *idx, uint32_t now) {
  int n = 0;
  for (int i = 0; i < 8; i++) if (att[i].used && now - att[i].last < ATTACK_END_MS) idx[n++] = i;
  for (int i = 1; i < n; i++)
    for (int j = i; j > 0 && att[idx[j]].count > att[idx[j - 1]].count; j--) { int t = idx[j]; idx[j] = idx[j - 1]; idx[j - 1] = t; }
  return n;
}

void hot(uint32_t now, uint8_t ch) {
  lastHot = now;
  if (attack) return;
  attack = true;
  attackStart = now;
  attackStartPkts = deauthRaw;
  locked = true;                 // stay on the attacked channel to capture details
  hopTo(ch);
  state = ST_ALERT;
  stateStart = now;
  Serial.printf("[!] DEAUTH ATTACK on channel %u\n", ch);
}

void endAttack(uint32_t now) {
  attack = false;
  lastWasCombo = comboTwin >= 0;
  comboTwin = -1;
  endDur = now - attackStart;
  endPkts = deauthRaw - attackStartPkts;
  locked = false;
  state = ST_ENDED;
  stateStart = now;
  Serial.printf("[+] Attack ended: %lus, %lu frames\n", (unsigned long)(endDur / 1000), (unsigned long)endPkts);
}

// during a deauth attack, look for an evil twin of the attacked network
void checkCombo(uint32_t now) {
  if (!attack || comboTwin >= 0) return;
  int idx[8];
  int n = activeAttackers(idx, now);
  int pick = -1;
  const uint8_t *realMac = nullptr;
  bool known = false;
  for (int i = 0; i < 4 && pick < 0; i++) {
    if (!twinActive(twins[i], now)) continue;
    for (int k = 0; k < n && pick < 0; k++) {          // deauth frames pretend to come from the REAL AP
      Attacker &a = att[idx[k]];
      if (macEq(a.bss, twins[i].a) || macEq(a.src, twins[i].a)) { pick = i; realMac = twins[i].a; known = true; }
      else if (macEq(a.bss, twins[i].b) || macEq(a.src, twins[i].b)) { pick = i; realMac = twins[i].b; known = true; }
    }
  }
  if (pick < 0) {                                       // no direct match: any active twin, guess the open one is fake
    for (int i = 0; i < 4 && pick < 0; i++) {
      if (!twinActive(twins[i], now)) continue;
      pick = i;
      Net *na = findNet(twins[i].a);
      realMac = (na && na->open) ? twins[i].b : twins[i].a;
    }
  }
  if (pick < 0) return;
  Twin &t = twins[pick];
  comboTwin = pick;
  comboKnown = known;
  t.shown = true;
  memcpy(comboReal, realMac, 6);
  memcpy(comboFake, macEq(realMac, t.a) ? t.b : t.a, 6);
  state = ST_ALERT;
  stateStart = now;                                     // restart the alert with the combo intro
  Serial.printf("[!!] COMBO ATTACK: deauth + evil twin on \"%s\"\n", t.ssid);
}

// twin appears / disappears
void twinTick(uint32_t now) {
  for (int i = 0; i < 4; i++) {
    Twin &t = twins[i];
    if (!t.used) continue;
    bool act = twinActive(t, now);
    if (act && !t.active) t.shown = false;             // (re)appeared: alert again
    if (!act && t.active) {
      Serial.printf("[+] Evil twin gone: \"%s\"\n", t.ssid);
      if (t.shown && state == ST_SCAN) { twinSel = i; state = ST_TWINGONE; stateStart = now; }
    }
    t.active = act;
  }
}

void channelTick(uint32_t now) {
  if (now - lastHop < HOP_MS) return;
  uint32_t dt = now - lastHop;
  lastHop = now;
  uint32_t pc = pktCount, dc = deauthRaw;
  uint32_t dp = pc - hopPkt, dd = dc - hopDeauth;
  hopPkt = pc; hopDeauth = dc;
  uint32_t ac = authRaw, da = ac - hopAuth;
  hopAuth = ac;
  uint32_t est = da * 1000UL / imax(dt, 1);
  if (da > 0 && est >= AUTH_RATE) { authEst = est; threatHot(TH_AUTH, now); }
  chLevel[curCh] = dp;
  if (dp > chPeak[curCh]) chPeak[curCh] = dp;
  if (!locked) {
    if (dd > 0 && dd * 1000UL / imax(dt, 1) >= ATTACK_RATE) hot(now, curCh);   // flood on this channel
    else {
      if (dd > 0) holdUntil = now + DEAUTH_HOLD_MS;      // a few deauths: wait here for a handshake
      if ((int32_t)(now - holdUntil) >= 0) hopTo(curCh % CH_MAX + 1);
    }
  }
}

void secondTick(uint32_t now) {
  if (now - lastSec < 1000) return;
  lastSec = now;
  uint32_t dc = deauthRaw, pc = pktCount;
  deauthRate = dc - secDeauth; secDeauth = dc;
  pktRate = pc - secPkt; secPkt = pc;
  if (locked && deauthRate >= ATTACK_RATE) hot(now, curCh);
  for (int i = 0; i < 8; i++) if (att[i].used) { att[i].rate = att[i].count - att[i].prevCount; att[i].prevCount = att[i].count; }
  for (int c = 1; c <= CH_MAX; c++) {
    deauthChSec[c] = 0;
    chPeak[c] = chPeak[c] * 9 / 10;
  }
  for (int i = 0; i < 20; i++) if (ct[i].used && now - ct[i].last > 20000) ct[i].used = false;
  for (int i = 0; i < 24; i++) if (nets[i].used && now - nets[i].last > 120000) nets[i].used = false;
  if (attack && now - lastHot > ATTACK_END_MS) endAttack(now);
  // auth flood rate
  uint32_t ac = authRaw;
  authRate = ac - secAuth; secAuth = ac;
  if (authRate > authEst) authEst = authRate; else authEst = authEst * 3 / 4;   // fades when it stops
  // beacon flood: new networks in the last 10 s
  memmove(newPerSec + 1, newPerSec, sizeof(newPerSec) - sizeof(newPerSec[0]));
  newPerSec[0] = newNetSec;
  newNetSec = 0;
  floodCount = 0;
  for (int i = 0; i < 10; i++) floodCount += newPerSec[i];
  if (now > FLOOD_GRACE_MS && floodCount >= FLOOD_NEW) threatHot(TH_FLOOD, now);
  camTick(now);
  threatTick(now);
}

void ledSet(int level) { analogWrite(LED_PIN, 1023 - constrain(level, 0, 1023)); }   // built-in LED is on when LOW

float huntStrength(uint32_t now) {
  if (now - huntLastFrame > 4000 || huntRssi < -99) return 0;
  return clamp01((huntRssi + 95) / 65.0f);           // -95 dBm = 0 (far) ... -30 dBm = 1 (right here)
}

void ledTick(uint32_t now) {
  uint32_t d = deauthRaw;
  if (d != ledSeenDeauth) { ledSeenDeauth = d; ledFlashUntil = now + 40; }   // flash on every deauth frame
  if (state == ST_HUNT) {                             // metal detector: brighter and faster ticks when closer
    float sgl = huntStrength(now);
    uint32_t period = 1000 - (uint32_t)(sgl * 920);
    int glow = 20 + (int)(sgl * sgl * 700);
    ledSet((now % period) < 35 ? 1023 : glow);
    return;
  }
  bool on;
  if (attack && comboTwin >= 0) on = (now / 40) % 2;                         // strobe: combo attack
  else if (attack) on = (now / 80) % 2;                                       // fast blink during attack
  else if (state == ST_TWIN) { uint32_t m = now % 1000; on = m < 80 || (m > 180 && m < 260); }   // double blink
  else if (state == ST_THREAT) { uint32_t m = now % 1200; on = m < 70 || (m > 150 && m < 220) || (m > 300 && m < 370); }  // triple
  else if (state == ST_ENDED) on = (now / 400) % 2;                            // slow blink: attack just ended
  else on = (int32_t)(ledFlashUntil - now) > 0;
  ledSet(on ? 1023 : 0);
}

// ================== VIEW: RADAR ==================
void drawRadar(uint32_t now) {
  const int cx = 31, cy = 33, R = 29;
  oled.drawCircle(cx, cy, R, WH);
  for (int a = 0; a < 360; a += 10) {
    float r = a * DEG_TO_RAD;
    oled.drawPixel(cx + cosf(r) * 19, cy + sinf(r) * 19, WH);
    if (a % 30 == 0) oled.drawPixel(cx + cosf(r) * 9, cy + sinf(r) * 9, WH);
  }
  for (int i = -R + 2; i <= R - 2; i += 3) { oled.drawPixel(cx + i, cy, WH); oled.drawPixel(cx, cy + i, WH); }

  // sweep with a fading trail
  float sa = fmodf(now * 0.0035f, TWO_PI);
  for (int k = 0; k < 7; k++) {
    float a = sa - k * 0.065f, ca = cosf(a), sn = sinf(a);
    for (int r = 2; r < R; r++) {
      if (k && ((r + k) % (k + 1))) continue;
      oled.drawPixel(cx + ca * r, cy + sn * r, WH);
    }
  }
  // contacts light up after the sweep passes them
  for (int i = 0; i < 20; i++) {
    if (!ct[i].used) continue;
    uint32_t h = macHash(ct[i].mac);
    float ang = (h % 628) / 100.0f;
    int dist = constrain(map(ct[i].rssi, -95, -30, R - 3, 5), 4, R - 3);
    int x = cx + cosf(ang) * dist, y = cy + sinf(ang) * dist;
    float diff = fmodf(sa - ang + 2 * TWO_PI, TWO_PI);
    if (ct[i].evil) {
      if ((now / 150) % 2) { oled.drawLine(x - 3, y - 3, x + 3, y + 3, WH); oled.drawLine(x - 3, y + 3, x + 3, y - 3, WH); }
      oled.drawCircle(x, y, 5, WH);
    } else if (diff < 0.35f) oled.fillCircle(x, y, 2, WH);
    else if (diff < 1.3f) { oled.drawPixel(x, y, WH); oled.drawPixel(x + 1, y, WH); }
    else if (diff < 2.4f) oled.drawPixel(x, y, WH);
  }

  // right panel
  char b[24];
  int dots = (now / 300) % 4;
  // badges for threats that are still going on (cycle through them)
  const char *lab[8];
  int nl = 0;
  bool twin = false;
  for (int i = 0; i < 4; i++) twin |= twinActive(twins[i], now);
  if (twin) lab[nl++] = "TWIN!";
  if (th[TH_CAPTURE].active) lab[nl++] = "PASS!";
  if (th[TH_AUTH].active) lab[nl++] = "AUTH!";
  if (th[TH_KARMA].active) lab[nl++] = "KARMA";
  if (th[TH_FLOOD].active) lab[nl++] = "FLOOD";
  if (th[TH_TOOL].active) lab[nl++] = tool.pwn ? "PWN!" : "TOOL!";
  if (th[TH_CAM].active) lab[nl++] = "CAM!";
  if (th[TH_DRONE].active) lab[nl++] = "DRONE";
  if (nl) {
    if ((now / 300) % 2) { oled.fillRect(64, 0, 40, 9, WH); txt(66, 1, lab[(now / 1200) % nl], 1, BK); }
  } else {
    snprintf(b, sizeof b, "SCAN%.*s", dots, "...");
    txt(66, 0, b, 1, WH);
  }
  txt(66, 12, "CH", 1, WH);
  snprintf(b, sizeof b, "%02u", curCh);
  txt(80, 10, b, 2, WH);
  int devs = 0;
  for (int i = 0; i < 20; i++) devs += ct[i].used;
  snprintf(b, sizeof b, "%d", devs);
  txt(128 - strlen(b) * 6, 10, b, 1, WH);
  txt(110, 18, "dev", 1, WH);
  snprintf(b, sizeof b, "PKT/s %lu", (unsigned long)pktRate);
  txt(66, 28, b, 1, WH);
  snprintf(b, sizeof b, "DEAUTH %lu", (unsigned long)deauthRate);
  txt(66, 38, b, 1, WH);
  // mini spectrum
  uint16_t mx = 1;
  for (int c = 1; c <= CH_MAX; c++) mx = max(mx, chPeak[c]);
  for (int c = 1; c <= CH_MAX; c++) {
    int x = 66 + (c - 1) * 4;
    int h = imax(1, chLevel[c] * 11 / mx);
    if (chDeauthAt[c] && now - chDeauthAt[c] < 3000) { if ((now / 150) % 2) oled.fillRect(x, 52, 3, 11, WH); }
    else oled.fillRect(x, 63 - h, 3, h, WH);
    if (c == curCh) oled.drawFastHLine(x, 49, 3, WH);
  }
}

// ================== ALERT ==================
void warnTriangle(int cx, int cy, int s, uint16_t c) {
  oled.fillTriangle(cx, cy - s, cx - s, cy + s * 3 / 4, cx + s, cy + s * 3 / 4, c);
}

void drawAlert(uint32_t now) {
  if (comboTwin >= 0) { drawCombo(now); return; }
  uint32_t t = now - stateStart;
  char b[28], mac[18];
  if (t < 1600) {                                  // intro: warning zooms in, screen flashes and glitches
    int s = 6 + ease(t / 700.0f) * 24;
    int sx = (t < 900) ? random(-3, 4) : 0;
    warnTriangle(64 + sx, 30, s, WH);
    if (s > 12) txt(61 + sx, 18 + s / 4, "!", s > 22 ? 2 : 1, BK);
    if (t > 600) {
      oled.fillRect(0, 50, 128, 14, BK);
      txtC(52, "DEAUTH DETECTED", 1, WH);
    }
    if (t < 1000) for (uint8_t p = 0; p < 8; p++) if (random(3) == 0) shiftPage(p, random(-10, 11));
    if ((t / 120) % 2) oled.fillRect(0, 0, 128, 64, INV);
    return;
  }
  // header: moving hazard stripes
  oled.fillRect(0, 0, 128, 11, WH);
  int off = (now / 40) % 12;
  for (int x = -12 + off; x < 128; x += 12) {
    oled.fillTriangle(x, 11, x + 6, 0, x + 10, 0, BK);
    oled.fillTriangle(x, 11, x + 4, 11, x + 10, 0, BK);
  }
  bool blink = (now / 300) % 2;
  oled.fillRect(17, 1, 94, 9, blink ? BK : WH);
  txtC(2, "DEAUTH ATTACK", 1, blink ? WH : BK);

  int idx[8];
  int n = activeAttackers(idx, now);
  if (n == 0) { txtC(28, "waiting for frames", 1, WH); return; }
  int sel = ((t - 1600) / ATTACKER_MS) % n;        // several attackers: show each in turn
  Attacker &a = att[idx[sel]];
  fmtMac(mac, a.src);
  snprintf(b, sizeof b, "SRC %s", mac);  txt(0, 13, b, 1, WH);
  if (isBroadcast(a.dst)) snprintf(b, sizeof b, "DST ALL DEVICES");
  else { fmtMac(mac, a.dst); snprintf(b, sizeof b, "DST %s", mac); }
  txt(0, 22, b, 1, WH);
  fmtMac(mac, a.bss);
  snprintf(b, sizeof b, "AP  %s", mac);  txt(0, 31, b, 1, WH);
  snprintf(b, sizeof b, "CH %u  RSSI %ddBm", a.ch, a.rssi);  txt(0, 40, b, 1, WH);
  snprintf(b, sizeof b, "PKTS %lu  %lu/s", (unsigned long)a.count, (unsigned long)a.rate);  txt(0, 49, b, 1, WH);
  // footer: attacker index, attack time, signal meter
  snprintf(b, sizeof b, "%d/%d", sel + 1, n);
  txt(0, 57, b, 1, WH);
  snprintf(b, sizeof b, "%lus", (unsigned long)((now - attackStart) / 1000));
  txt(30, 57, b, 1, WH);
  int bars = constrain(map(a.rssi, -95, -35, 0, 5), 0, 5);
  for (int i = 0; i < 5; i++) {
    int h = 2 + i;
    if (i < bars) oled.fillRect(100 + i * 5, 63 - h, 4, h, WH); else oled.drawPixel(101 + i * 5, 63, WH);
  }
}

// ================== EVIL TWIN ALERT ==================
void wifiIcon(int cx, int cy, uint16_t c) {
  oled.fillCircle(cx, cy, 2, c);
  for (int r = 6; r <= 14; r += 4) {
    oled.drawCircleHelper(cx, cy, r, 0x1 | 0x2, c);
    oled.drawCircleHelper(cx, cy, r - 1, 0x1 | 0x2, c);
  }
}

void netLine(int y, int num, const uint8_t *mac) {
  char b[28], m[18];
  fmtMac(m, mac);
  snprintf(b, sizeof b, "%d %s", num, m);
  txt(0, y, b, 1, WH);
  Net *n = findNet(mac);
  if (n) snprintf(b, sizeof b, "  ch%u %ddBm %s", n->ch, n->rssi, n->open ? "OPEN" : "LOCKED");
  else snprintf(b, sizeof b, "  (not seen now)");
  txt(0, y + 9, b, 1, WH);
}

void drawTwin(uint32_t now) {
  uint32_t t = now - stateStart;
  if (twinSel < 0) return;
  Twin &tw = twins[twinSel];
  if (t < 1800) {                       // intro: one WiFi icon splits into two, the copy turns evil
    float p = ease(t / 800.0f);
    int dx = p * 30;
    wifiIcon(64 - dx, 34, WH);
    bool flick = t > 700 && (t / 90) % 3 == 0;
    if (!flick) {
      wifiIcon(64 + dx, 34, WH);
      if (t > 900) {                    // devil horns on the copy
        int x = 64 + dx;
        oled.fillTriangle(x - 12, 18, x - 16, 10, x - 8, 16, WH);
        oled.fillTriangle(x + 12, 18, x + 16, 10, x + 8, 16, WH);
      }
    }
    if (t < 900) for (int y = 14; y < 40; y += 3) oled.drawPixel(64, y, WH);    // mirror line
    if (t > 1000 && t < 1300) for (uint8_t pg = 1; pg < 6; pg++) if (random(2)) shiftPage(pg, random(-6, 7));
    if (t > 700) txtC(48, "CLONE DETECTED", 1, WH);
    if (t > 700) txtC(57, tw.ssid, 1, WH);
    return;
  }
  // header with mirrored moving dots
  oled.fillRect(0, 0, 128, 11, WH);
  int off = (now / 60) % 8;
  for (int x = off; x < 64; x += 8) { oled.fillRect(x, 4, 3, 3, BK); oled.fillRect(124 - x, 4, 3, 3, BK); }
  bool blink = (now / 300) % 2;
  oled.fillRect(30, 1, 68, 9, blink ? BK : WH);
  txtC(2, "EVIL TWIN?", 1, blink ? WH : BK);
  char b[28];
  snprintf(b, sizeof b, "SSID %.16s", tw.ssid);
  txt(0, 13, b, 1, WH);
  netLine(22, 1, tw.a);
  netLine(40, 2, tw.b);
  Net *na = findNet(tw.a), *nb = findNet(tw.b);
  const char *verdict;
  if (na && nb && na->open != nb->open) verdict = "! open clone - DANGER";
  else if (memcmp(tw.a, tw.b, 3) != 0) verdict = "! different maker";
  else verdict = "same maker: mesh?";
  if (!blink || verdict[0] != '!') txt(0, 57, verdict, 1, WH);
}

// ================== COMBO ALERT ==================
void hazardHeader(uint32_t now, const char *title) {
  oled.fillRect(0, 0, 128, 11, WH);
  int off = (now / 40) % 12;
  for (int x = -12 + off; x < 128; x += 12) {
    oled.fillTriangle(x, 11, x + 6, 0, x + 10, 0, BK);
    oled.fillTriangle(x, 11, x + 4, 11, x + 10, 0, BK);
  }
  bool blink = (now / 250) % 2;
  int w = strlen(title) * 6 + 6;
  oled.fillRect((128 - w) / 2, 1, w, 9, blink ? BK : WH);
  txtC(2, title, 1, blink ? WH : BK);
}

void horns(int x, int y) {
  oled.fillTriangle(x - 12, y, x - 16, y - 8, x - 8, y - 2, WH);
  oled.fillTriangle(x + 12, y, x + 16, y - 8, x + 8, y - 2, WH);
}

void drawCombo(uint32_t now) {
  uint32_t t = now - stateStart;
  Twin &tw = twins[comboTwin];
  char b[28], m[18];
  if (t < 2400) {
    // real AP (left) is hit by lightning, victims fly over to the evil twin (right)
    wifiIcon(28, 32, WH);
    wifiIcon(100, 32, WH);
    horns(100, 18);
    if ((t / 90) % 3 != 2) {
      int bx = 28 + ((int)(t / 250) % 3 - 1) * 7;
      for (int k = 0; k < 2; k++) {
        oled.drawLine(bx + k, 0, bx - 4 + k, 6, WH);
        oled.drawLine(bx - 4 + k, 6, bx + 2 + k, 8, WH);
        oled.drawLine(bx + 2 + k, 8, bx - 3 + k, 16, WH);
      }
    }
    for (int k = 0; k < 4; k++) {
      float ph = fmodf(t / 650.0f + k * 0.25f, 1.0f);
      oled.fillCircle(42 + ph * 44, 30 - sinf(ph * PI) * 12, 1, WH);
    }
    if (t < 900 && (t / 110) % 2) oled.fillRect(0, 0, 128, 64, INV);
    if (t > 600) {
      oled.fillRect(0, 45, 128, 19, BK);
      txtC(46, "COMBO ATTACK", 1, WH);
      txtC(56, "deauth + evil twin", 1, WH);
    }
    return;
  }
  hazardHeader(now, "COMBO ATTACK");
  snprintf(b, sizeof b, "SSID %.16s", tw.ssid);
  txt(0, 13, b, 1, WH);
  fmtMac(m, comboReal);
  snprintf(b, sizeof b, "AP  %s", m);
  txt(0, 22, b, 1, WH);
  fmtMac(m, comboFake);
  snprintf(b, sizeof b, "TWN %s", m);
  txt(0, 31, b, 1, WH);
  Net *nf = findNet(comboFake);
  if (nf) snprintf(b, sizeof b, "TWIN ch%u %s %ddBm", nf->ch, nf->open ? "OPEN" : "LOCK", nf->rssi);
  else snprintf(b, sizeof b, "TWIN (signal lost)");
  txt(0, 40, b, 1, WH);
  snprintf(b, sizeof b, "DEAUTH %lu/s on ch%u", (unsigned long)deauthRate, curCh);
  txt(0, 49, b, 1, WH);
  if ((now / 400) % 2) txt(0, 57, comboKnown ? "victims -> twin!" : "(possible combo)", 1, WH);
  snprintf(b, sizeof b, "%lus", (unsigned long)((now - attackStart) / 1000));
  txt(128 - strlen(b) * 6, 57, b, 1, WH);
}

void drawTwinGone(uint32_t now) {
  uint32_t t = now - stateStart;
  Twin &tw = twins[twinSel];
  wifiIcon(64, 32, WH);
  horns(64, 18);
  for (int i = 0; i < (int)(t / 3); i++) oled.drawPixel(random(44, 86), random(6, 36), BK);   // dissolves
  txtC(44, "TWIN GONE", 1, WH);
  txtC(55, tw.ssid, 1, WH);
}

// ================== KARMA / BEACON FLOOD / AUTH FLOOD ==================
void routerIcon(int cx, int cy) {
  oled.fillRoundRect(cx - 12, cy - 4, 24, 10, 2, WH);
  oled.drawLine(cx - 8, cy - 4, cx - 11, cy - 12, WH);
  oled.drawLine(cx + 8, cy - 4, cx + 11, cy - 12, WH);
  for (int i = 0; i < 4; i++) oled.drawPixel(cx - 7 + i * 4, cy + 1, BK);
}

void pineapple(int cx, int cy) {
  oled.fillRoundRect(cx - 7, cy - 6, 14, 18, 7, WH);
  for (int y = -3; y < 11; y += 4)
    for (int x = -4; x <= 4; x += 4) oled.drawPixel(cx + x + ((y / 4) % 2) * 2, cy + y, BK);
  oled.fillTriangle(cx, cy - 16, cx - 4, cy - 6, cx + 4, cy - 6, WH);
  oled.fillTriangle(cx - 7, cy - 12, cx - 2, cy - 6, cx + 1, cy - 8, WH);
  oled.fillTriangle(cx + 7, cy - 12, cx + 2, cy - 6, cx - 1, cy - 8, WH);
}

void bubble(int x, int y, const char *s) {
  char b[10];
  snprintf(b, sizeof b, "%.8s", s);
  int w = strlen(b) * 6 + 5;
  if (x + w > 128) x = 128 - w;
  if (x < 0) x = 0;
  oled.fillRoundRect(x, y, w, 11, 3, BK);
  oled.drawRoundRect(x, y, w, 11, 3, WH);
  txt(x + 3, y + 2, b, 1, WH);
}

void drawThreat(uint32_t now) {
  uint32_t t = now - stateStart;
  char b[28], m[18];
  if (thSel == TH_CAPTURE) {
    if (t < 2600) {                                  // handshake flies between router and phone, a spy eye copies it
      routerIcon(20, 36);
      oled.drawRoundRect(100, 26, 13, 21, 3, WH);    // phone
      oled.drawFastHLine(104, 43, 5, WH);
      int msg = (t / 500) % 4;
      float ph = (t % 500) / 500.0f;
      int x0 = (msg % 2 == 0) ? 34 : 98, x1 = (msg % 2 == 0) ? 98 : 34;
      int x = x0 + (x1 - x0) * ph;
      oled.fillCircle(x, 34, 2, WH);
      oled.fillCircle(64, 34 - (int)(ph * 22), 1, WH);               // stolen copy rising to the eye
      oled.fillRoundRect(52, 2, 24, 10, 5, WH);
      oled.fillCircle(64 + (x - 64) / 12, 7, 3, BK);                // pupil follows the message
      char mb[4];
      snprintf(mb, sizeof mb, "%d/4", msg + 1);
      txt(56, 40, mb, 1, WH);
      if (t > 800) { oled.fillRect(0, 48, 128, 16, BK); txtC(48, "PASSWORD CAPTURE", 1, WH); txtC(57, "ATTEMPT", 1, WH); }
      return;
    }
    hazardHeader(now, "PASSWORD CAPTURE");
    fmtMac(m, capBss);
    snprintf(b, sizeof b, "AP  %s", m); txt(0, 13, b, 1, WH);
    fmtMac(m, capCli);
    snprintf(b, sizeof b, "DEV %s", m); txt(0, 22, b, 1, WH);
    snprintf(b, sizeof b, "handshake %u msg ch%u", capMsgs, capCh); txt(0, 31, b, 1, WH);
    snprintf(b, sizeof b, "deauth %lus before", (unsigned long)(capDeauthAgo / 1000)); txt(0, 40, b, 1, WH);
    txt(0, 49, "WiFi password may be", 1, WH);
    if ((now / 400) % 2) txt(0, 57, "cracked: use strong!", 1, WH);
  } else if (thSel == TH_AUTH) {
    if (t < 2200) {                                  // swarm of fake devices rushing the router
      int shake = t > 700 ? random(-2, 3) : 0;
      routerIcon(64 + shake, 28);
      for (int k = 0; k < 18; k++) {
        float a = (hsh8(k) / 255.0f) * TWO_PI;
        float ph = fmodf(t / 700.0f + k / 18.0f, 1.0f);
        float r = 64 - ph * 50;
        oled.fillRect(64 + cosf(a) * r, 28 + sinf(a) * r * 0.6f, 2, 2, WH);
      }
      if (t > 600) { oled.fillRect(0, 45, 128, 19, BK); txtC(46, "AUTH FLOOD", 1, WH); txtC(56, "fake devices!", 1, WH); }
      return;
    }
    hazardHeader(now, "AUTH FLOOD");
    fmtMac(m, authBss);
    snprintf(b, sizeof b, "TO  %s", m); txt(0, 13, b, 1, WH);
    snprintf(b, sizeof b, "CH %u  %lu req/s", authCh, (unsigned long)authEst); txt(0, 22, b, 1, WH);
    snprintf(b, sizeof b, "%d fake devices", countRecent(authSrc, 32, now, 5000)); txt(0, 31, b, 1, WH);
    snprintf(b, sizeof b, "type: %s", authType ? "association" : "authentication"); txt(0, 40, b, 1, WH);
    int w = constrain((int)(authEst * 120 / 200), 4, 120);
    oled.drawRect(0, 49, 124, 6, WH);
    for (int x = 2; x < w; x += 3) if ((x / 3 + now / 60) % 4) oled.drawFastVLine(x, 51, 2, WH);
    if ((now / 400) % 2) txt(0, 57, "router may slow down", 1, WH);
  } else if (thSel == TH_KARMA) {
    KarmaTrack &k = kt[karmaSel];
    if (t < 2400) {                                  // pineapple shouting many network names
      pineapple(64, 30);
      const int bx[4] = {2, 84, 0, 86}, by[4] = {4, 6, 30, 32};
      int shown = imin(4, t / 450);
      for (int i = 0; i < shown; i++) {
        const char *nm = i < k.n && i < 3 ? k.names[i] : "...";
        int pop = (t - i * 450) < 120 ? -2 : 0;
        bubble(bx[i], by[i] + pop, nm);
      }
      if (t > 900) { oled.fillRect(0, 47, 128, 17, BK); txtC(48, "KARMA ATTACK", 1, WH); txtC(57, "one MAC, many names", 1, WH); }
      return;
    }
    hazardHeader(now, "KARMA/PINEAPPLE");
    fmtMac(m, k.mac);
    snprintf(b, sizeof b, "MAC %s", m); txt(0, 13, b, 1, WH);
    snprintf(b, sizeof b, "uses %u WiFi names:", k.n); txt(0, 22, b, 1, WH);
    for (int i = 0; i < 3 && i < k.n; i++) { snprintf(b, sizeof b, "- %s", k.names[i]); txt(0, 31 + i * 9, b, 1, WH); }
    snprintf(b, sizeof b, "ch%u %ddBm", k.ch, k.rssi); txt(0, 57, b, 1, WH);
    if ((now / 400) % 2) txt(76, 57, "TRAP!", 1, WH);
  } else if (thSel == TH_TOOL) {
    if (t < 2400) {
      // terminal typing, then a Pwnagotchi face or a skull
      const char *l1 = "> scanning beacons", *l2 = "> signature match!";
      int n1 = imin(strlen(l1), t / 30), n2 = t > 700 ? imin(strlen(l2), (t - 700) / 30) : 0;
      char s1[24], s2[24];
      memcpy(s1, l1, n1); s1[n1] = 0;
      memcpy(s2, l2, n2); s2[n2] = 0;
      txt(0, 0, s1, 1, WH);
      txt(0, 9, s2, 1, WH);
      if (t > 1300) {
        if (tool.pwn) {
          const char *face = (t / 300) % 3 == 0 ? "(-_-)" : ((t / 300) % 3 == 1 ? "(O_O)" : "(^_^)");
          txtC(24, face, 2, WH);
          txtC(48, "PWNAGOTCHI", 1, WH);
          txtC(57, tool.name, 1, WH);
        } else {
          oled.fillCircle(64, 30, 9, WH);           // skull
          oled.fillRect(59, 36, 11, 6, WH);
          oled.fillCircle(60, 29, 2, BK);
          oled.fillCircle(68, 29, 2, BK);
          for (int x = 60; x < 69; x += 3) oled.drawFastVLine(x, 38, 4, BK);
          txtC(48, "HACK TOOL", 1, WH);
          txtC(57, tool.name, 1, WH);
        }
      }
      return;
    }
    hazardHeader(now, tool.pwn ? "PWNAGOTCHI" : "HACK TOOL");
    snprintf(b, sizeof b, "%s %.16s", tool.pwn ? "NAME" : "TOOL", tool.name); txt(0, 13, b, 1, WH);
    if (tool.ssid[0]) { snprintf(b, sizeof b, "SSID %.16s", tool.ssid); txt(0, 22, b, 1, WH); }
    fmtMac(m, tool.mac);
    snprintf(b, sizeof b, "MAC %s", m); txt(0, 31, b, 1, WH);
    snprintf(b, sizeof b, "ch%u  %ddBm", tool.ch, tool.rssi); txt(0, 40, b, 1, WH);
    txt(0, 49, tool.pwn ? "collects handshakes" : "WiFi attack device", 1, WH);
    if ((now / 400) % 2) txt(0, 57, "hunt starts next...", 1, WH);
  } else if (thSel == TH_CAM) {
    if (t < 2400) {
      // camera with a pulsing lens, REC dot and closing focus brackets
      int z = t < 1000 ? 30 - t / 50 : 10;
      oled.fillRoundRect(46, 18, 36, 24, 4, WH);
      oled.fillRect(56, 13, 10, 6, WH);
      int lr = 7 + (int)(sinf(t / 150.0f) * 2);
      oled.fillCircle(64, 30, lr + 2, BK);
      oled.drawCircle(64, 30, lr, WH);
      oled.fillCircle(64, 30, lr / 3 + 1, WH);
      for (int sx = -1; sx <= 1; sx += 2)
        for (int sy = -1; sy <= 1; sy += 2) {
          int cx = 64 + sx * (z + 22), cy = 30 + sy * (z + 14);
          oled.drawFastHLine(sx < 0 ? cx : cx - 5, cy, 6, WH);
          oled.drawFastVLine(cx, sy < 0 ? cy : cy - 5, 6, WH);
        }
      if ((t / 400) % 2) { oled.fillCircle(6, 5, 3, WH); txt(12, 2, "REC", 1, WH); }
      if (t > 900) { oled.fillRect(0, 48, 128, 16, BK); txtC(49, "HIDDEN CAMERA?", 1, WH); txtC(57, cam.brand, 1, WH); }
      return;
    }
    hazardHeader(now, "CAMERA NEARBY");
    snprintf(b, sizeof b, "WHAT %.16s", cam.brand); txt(0, 13, b, 1, WH);
    snprintf(b, sizeof b, "WHY  %.16s", cam.reason); txt(0, 22, b, 1, WH);
    fmtMac(m, cam.mac);
    snprintf(b, sizeof b, "MAC %s", m); txt(0, 31, b, 1, WH);
    snprintf(b, sizeof b, "ch%u  %ddBm", cam.ch, cam.rssi); txt(0, 40, b, 1, WH);
    txt(0, 49, "check the room", 1, WH);
    if ((now / 400) % 2) txt(0, 57, "hunt starts next...", 1, WH);
  } else if (thSel == TH_DRONE) {
    if (t < 2400) {
      // quadcopter flying in and hovering, rotors spinning
      int dx = t < 1000 ? -40 + (int)(ease(t / 1000.0f) * 104) : 64;
      int dy = 26 + (int)(sinf(t / 200.0f) * 3);
      oled.drawLine(dx - 14, dy - 8, dx + 14, dy + 8, WH);
      oled.drawLine(dx - 14, dy + 8, dx + 14, dy - 8, WH);
      oled.fillRoundRect(dx - 5, dy - 3, 10, 7, 2, WH);
      for (int i = 0; i < 4; i++) {
        int rx = dx + (i % 2 ? 14 : -14), ry = dy + (i < 2 ? -8 : 8);
        int w = (t / 40 + i) % 2 ? 7 : 3;
        oled.drawFastHLine(rx - w, ry - 1, w * 2, WH);
      }
      for (int k = 0; k < 3; k++) {                // signal waves going down
        int r = (int)((t / 8 + k * 10) % 30);
        oled.drawCircleHelper(dx, dy + 4, r, 0x4 | 0x8, WH);
      }
      if (t > 900) { oled.fillRect(0, 48, 128, 16, BK); txtC(49, "DRONE DETECTED", 1, WH); txtC(57, drone.kind, 1, WH); }
      return;
    }
    hazardHeader(now, "DRONE NEARBY");
    snprintf(b, sizeof b, "TYPE %.16s", drone.kind); txt(0, 13, b, 1, WH);
    if (drone.ssid[0]) { snprintf(b, sizeof b, "SSID %.16s", drone.ssid); txt(0, 22, b, 1, WH); }
    if (drone.id[0]) { snprintf(b, sizeof b, "ID %.18s", drone.id); txt(0, 31, b, 1, WH); }
    fmtMac(m, drone.mac);
    snprintf(b, sizeof b, "MAC %s", m); txt(0, 40, b, 1, WH);
    snprintf(b, sizeof b, "ch%u  %ddBm", drone.ch, drone.rssi); txt(0, 49, b, 1, WH);
    if ((now / 400) % 2) txt(0, 57, "hunt starts next...", 1, WH);
  } else {
    if (t < 2400) {                                  // fake network names raining down
      for (int c = 0; c < 6; c++) {
        int x = c * 22;
        int y = (int)((t / (6 + c % 3) + c * 23) % 90) - 20;
        const char *nm = floodNames[c % 3][0] ? floodNames[c % 3] : "FreeWiFi";
        char s2[5];
        snprintf(s2, sizeof s2, "%.3s", nm);
        txt(x, y, s2, 1, WH);
        txt(x, y - 22, s2, 1, WH);
      }
      if (t > 600) {
        oled.fillRoundRect(20, 22, 88, 20, 4, BK);
        oled.drawRoundRect(20, 22, 88, 20, 4, WH);
        txtC(28, "BEACON FLOOD", 1, WH);
      }
      return;
    }
    hazardHeader(now, "BEACON FLOOD");
    snprintf(b, sizeof b, "%u new networks", floodCount); txt(0, 13, b, 1, WH);
    txt(0, 22, "in 10 seconds (spam)", 1, WH);
    txt(0, 31, "latest names:", 1, WH);
    for (int i = 0; i < 2; i++) {
      const char *nm = floodNames[(floodNameIdx + 2 - i) % 3];
      snprintf(b, sizeof b, "- %s", nm[0] ? nm : "?");
      txt(0, 40 + i * 9, b, 1, WH);
    }
    if ((now / 400) % 2) txt(0, 57, "fake WiFi list!", 1, WH);
  }
}

// ================== HUNT MODE ==================
bool huntActive(uint32_t now) {
  switch (huntType) {
    case H_DEAUTH: return attack;
    case H_AUTH:   return th[TH_AUTH].active;
    case H_TWIN:   return twinSel >= 0 && twinActive(twins[twinSel], now) && now - stateStart < HUNT_MAX_MS;
    case H_KARMA:  return th[TH_KARMA].active && now - stateStart < HUNT_MAX_MS;
    case H_TOOL:   return th[TH_TOOL].active && now - stateStart < HUNT_MAX_MS;
    case H_CAM:    return th[TH_CAM].active && now - stateStart < HUNT_MAX_MS;
    case H_DRONE:  return th[TH_DRONE].active && now - stateStart < HUNT_MAX_MS;
    default:       return false;
  }
}

void startHunt(uint8_t type, const uint8_t *mac, int8_t rssi, uint8_t ch, uint32_t now) {
  huntType = type;
  if (mac) memcpy(huntMac, mac, 6); else memset(huntMac, 0, 6);
  huntRssi = rssi ? rssi : -100;
  huntPeak = rssi ? rssi : -127;
  huntLastFrame = rssi ? now : 0;
  huntGoneAt = 0;
  if (ch >= 1 && ch <= CH_MAX) { locked = true; hopTo(ch); }   // listen only on the target's channel
  state = ST_HUNT;
  stateStart = now;
}

void stopHunt() {
  huntType = H_NONE;
  if (!attack) locked = false;
  state = ST_SCAN;
}

void drawHunt(uint32_t now) {
  static const char *LBL[8] = {"", "DEAUTH", "AUTH FLOOD", "EVIL TWIN", "KARMA", "HACK TOOL", "CAMERA", "DRONE"};
  char b[28];
  // header
  oled.fillRect(0, 0, 128, 10, WH);
  if (huntType == H_DEAUTH || huntType == H_AUTH) {
    int idx[8];
    if (huntType == H_DEAUTH && activeAttackers(idx, now)) memcpy(huntMac, att[idx[0]].src, 6);
  }
  snprintf(b, sizeof b, "HUNT %02X:%02X:%02X:%02X", huntMac[2], huntMac[3], huntMac[4], huntMac[5]);
  txt(2, 1, b, 1, BK);
  snprintf(b, sizeof b, "ch%u", curCh);
  txt(128 - strlen(b) * 6 - 1, 1, b, 1, BK);

  float sgl = huntStrength(now);
  bool lost = now - huntLastFrame > 4000 || huntRssi < -99;
  const int cx = 64, cy = 48, R = 34;
  // gauge: ticks light up with signal strength
  for (int i = 0; i <= 15; i++) {
    float a = PI + i * PI / 15;
    float lvl = i / 15.0f;
    int x1 = cx + cosf(a) * (R - 8), y1 = cy + sinf(a) * (R - 8);
    int x2 = cx + cosf(a) * R, y2 = cy + sinf(a) * R;
    if (lvl <= sgl && !lost) { oled.drawLine(x1, y1, x2, y2, WH); oled.drawLine(x1 + 1, y1, x2 + 1, y2, WH); }
    else oled.drawPixel(x2, y2, WH);
  }
  // pulse rings from the hub, faster when closer
  uint32_t period = 1200 - (uint32_t)(sgl * 1000);
  int pr = (now % period) * 24 / period;
  if (!lost) oled.drawCircleHelper(cx, cy, pr, 0x1 | 0x2, WH);
  // needle (wobbles a little like a real meter)
  float na = PI + (lost ? 0.05f : sgl) * PI + sinf(now / 90.0f) * 0.04f * sgl;
  oled.drawLine(cx, cy, cx + cosf(na) * (R - 4), cy + sinf(na) * (R - 4), WH);
  oled.drawLine(cx + 1, cy, cx + 1 + cosf(na) * (R - 4), cy + sinf(na) * (R - 4), WH);
  oled.fillCircle(cx, cy, 3, WH);

  const char *word;
  if (lost) word = (now / 400) % 2 ? "NO SIGNAL" : "";
  else if (sgl < 0.25f) word = "FAR AWAY";
  else if (sgl < 0.5f) word = "GETTING WARMER";
  else if (sgl < 0.75f) word = "NEAR";
  else word = (now / 150) % 2 ? "VERY CLOSE!" : "";
  oled.fillRect(0, 51, 128, 13, BK);
  txtC(51, word, 1, WH);
  if (!lost) snprintf(b, sizeof b, "%ddBm", (int)huntRssi); else snprintf(b, sizeof b, "--dBm");
  txt(0, 57, b, 1, WH);
  txt(128 - strlen(LBL[huntType]) * 6, 57, LBL[huntType], 1, WH);
  if (huntGoneAt) { oled.fillRoundRect(24, 20, 80, 16, 4, BK); oled.drawRoundRect(24, 20, 80, 16, 4, WH); txtC(24, "TARGET GONE", 1, WH); }
}

uint8_t hsh8(int k) { return (uint8_t)((k * 97 + 31) * 53); }

void drawBanner(uint32_t now) {
  if (!bannerOn) return;
  uint32_t t = now - bannerStart;
  int y = 64 - imin(12, (int)(t / 15));
  if (t > PROBE_SHOW_MS - 180) y = 52 + (int)(t - (PROBE_SHOW_MS - 180)) / 15;
  oled.fillRect(0, y, 128, 12, BK);
  oled.drawRect(0, y, 128, 12, WH);
  char b[24];
  if (curBanner.type == 1) {                       // open WiFi: unlocked padlock + inverted OPEN tag
    oled.fillRect(3, y + 5, 7, 5, WH);
    oled.drawCircleHelper(5, y + 5, 2, 0x1 | 0x2, WH);
    oled.drawPixel(3, y + 5, BK);
    snprintf(b, sizeof b, "%.13s", curBanner.ssid);
    txt(13, y + 2, b, 1, WH);
    bool blink = (now / 250) % 2;
    oled.fillRect(98, y + 1, 29, 10, blink ? WH : BK);
    txt(101, y + 2, "OPEN", 1, blink ? BK : WH);
    return;
  }
  snprintf(b, sizeof b, "? %.13s", curBanner.ssid);
  txt(3, y + 2, b, 1, WH);
  snprintf(b, sizeof b, "%02X%02X", curBanner.mac[4], curBanner.mac[5]);
  txt(124 - 24, y + 2, b, 1, WH);
}

// ================== ATTACK ENDED ==================
void drawEnded(uint32_t now) {
  uint32_t t = now - stateStart;
  float p = ease(t / 900.0f);
  int s = 4 + p * 14, cx = 64, cy = 22;             // shield grows, then a check mark is drawn
  oled.fillRoundRect(cx - s, cy - s, s * 2, s, 3, WH);
  oled.fillTriangle(cx - s, cy - 1, cx + s, cy - 1, cx, cy + s + 2, WH);
  if (t > 900) {
    float q = clamp01((t - 900) / 400.0f);
    int x1 = cx - 7, y1 = cy - 2, x2 = cx - 2, y2 = cy + 4, x3 = cx + 8, y3 = cy - 7;
    for (int k = 0; k < 3; k++) {
      oled.drawLine(x1, y1 + k, x1 + (x2 - x1) * clamp01(q * 2), y1 + k + (y2 - y1) * clamp01(q * 2), BK);
      if (q > 0.5f) oled.drawLine(x2, y2 + k, x2 + (x3 - x2) * clamp01(q * 2 - 1), y2 + k + (y3 - y2) * clamp01(q * 2 - 1), BK);
    }
    for (int i = 0; i < 6; i++) {                   // sparkles
      float a = i * PI / 3 + t / 500.0f;
      int r = 24 + (t / 60) % 6;
      oled.drawPixel(cx + cosf(a) * r, cy + sinf(a) * r, WH);
    }
  }
  if (t > 600) {
    txtC(44, lastWasCombo ? "COMBO ENDED" : "ATTACK ENDED", 1, WH);
    char b[28];
    snprintf(b, sizeof b, "%lus  %lu frames", (unsigned long)(endDur / 1000), (unsigned long)endPkts);
    txtC(55, b, 1, WH);
  }
}

// ================== SCREEN SAVER ==================
bool saverOn(uint32_t now) { return SAVER_MS && state == ST_SCAN && now - lastActivity > SAVER_MS; }

void drawSaver(uint32_t now) {
  // a tiny radar drifting around the screen (avoids OLED burn-in), screen dimmed
  float t = now / 1000.0f;
  int x = 64 + sinf(t * 0.31f) * 48, y = 32 + sinf(t * 0.23f + 1) * 20;
  oled.drawCircle(x, y, 9, WH);
  float a = fmodf(now * 0.004f, TWO_PI);
  oled.drawLine(x, y, x + cosf(a) * 8, y + sinf(a) * 8, WH);
  oled.drawPixel(x, y, WH);
  int devs = 0;
  for (int i = 0; i < 20; i++) devs += ct[i].used;
  char b[12];
  snprintf(b, sizeof b, "%d", devs);
  txt(x + 12, y - 3, b, 1, WH);
}

// ================== BOOT ==================
void drawBoot(uint32_t now) {
  uint32_t t = now - stateStart;
  int scan = imin(64, t / 12);
  txtC(8, "DEAUTH", 2, WH);
  txtC(28, "DETECTOR", 2, WH);
  oled.fillRect(0, scan, 128, 64 - scan, BK);       // reveal with a scan line
  if (scan < 64) oled.drawFastHLine(0, scan, 128, WH);
  int noise = imax(0, 300 - (int)t / 3);
  for (int i = 0; i < noise; i++) oled.drawPixel(random(128), random(64), INV);
  if (t > 900) {
    // credit types out letter by letter
    const char *by = "by Gamkers";
    int n = imin(strlen(by), (t - 900) / 60);
    char b[20];
    memcpy(b, by, n);
    b[n] = 0;
    txt((128 - (int)strlen(by) * 6) / 2, 44, b, 1, WH);
    if (n < (int)strlen(by) && (t / 120) % 2) oled.fillRect((128 - (int)strlen(by) * 6) / 2 + n * 6, 44, 5, 8, WH);
    float p = clamp01((t - 900) / (float)(BOOT_MS - 1100));
    oled.drawRect(14, 56, 100, 6, WH);
    oled.fillRect(16, 58, 96 * p, 2, WH);
  }
}

// ================== SETUP / LOOP ==================
void setup() {
  Serial.begin(115200);
  pinMode(LED_PIN, OUTPUT);
  analogWriteRange(1023);
  analogWriteFreq(1000);
  ledSet(0);                      // off
  randomSeed(micros());

  Wire.begin(PIN_SDA, PIN_SCL);
  if (!oled.begin(SSD1306_SWITCHCAPVCC, OLED_ADDR)) {
    Serial.println(F("SSD1306 not found"));
    for (;;) delay(1000);
  }
  Wire.setClock(400000);
  oled.setTextWrap(false);

  startSniffer();
  stateStart = lastHop = lastSec = millis();
  Serial.println(F("Deauth detector running (passive, receive only)"));
}

void loop() {
  uint32_t now = millis();

  drainQueues(now);
  channelTick(now);
  secondTick(now);
  ledTick(now);
  twinTick(now);
  checkCombo(now);

  if (state == ST_BOOT && now - stateStart > BOOT_MS) state = ST_SCAN;
  if (state == ST_ENDED && now - stateStart > 4000) state = ST_SCAN;
  if (state == ST_TWIN && now - stateStart > TWIN_ALERT_MS) {
    Twin &tw = twins[twinSel];
    tw.shown = true;
    if (twinActive(tw, now)) {                    // hunt the copy: the newer one (or the open one)
      Net *na = findNet(tw.a), *nb = findNet(tw.b);
      Net *fake = (na && nb && na->open && !nb->open) ? na : nb;
      startHunt(H_TWIN, fake->bssid, fake->rssi, fake->ch, now);
    } else state = ST_SCAN;
  }
  if (state == ST_TWINGONE && now - stateStart > 3000) state = ST_SCAN;
  if (state == ST_THREAT && now - stateStart > THREAT_ALERT_MS) {
    th[thSel].alerted = true;
    if (attack) startHunt(H_DEAUTH, nullptr, 0, 0, now);
    else if (thSel == TH_KARMA && th[TH_KARMA].active) startHunt(H_KARMA, kt[karmaSel].mac, kt[karmaSel].rssi, kt[karmaSel].ch, now);
    else if (thSel == TH_AUTH && th[TH_AUTH].active) startHunt(H_AUTH, authBss, 0, authCh, now);
    else if (thSel == TH_TOOL && th[TH_TOOL].active) startHunt(H_TOOL, tool.mac, tool.rssi, tool.ch, now);
    else if (thSel == TH_CAM && th[TH_CAM].active) startHunt(H_CAM, cam.mac, cam.rssi, cam.ch, now);
    else if (thSel == TH_DRONE && th[TH_DRONE].active) startHunt(H_DRONE, drone.mac, drone.rssi, drone.ch, now);
    else state = ST_SCAN;
  }
  // a password capture attempt interrupts the deauth alert / hunt right away
  if ((state == ST_ALERT || state == ST_HUNT) && th[TH_CAPTURE].active && !th[TH_CAPTURE].alerted) {
    thSel = TH_CAPTURE; state = ST_THREAT; stateStart = now;
  }
  // deauth alert -> hunt mode after a while
  if (state == ST_ALERT && attack && now - stateStart > HUNT_AFTER_MS) {
    int idx[8];
    int n = activeAttackers(idx, now);
    startHunt(H_DEAUTH, n ? att[idx[0]].src : nullptr, n ? att[idx[0]].rssi : 0, 0, now);
  }
  if (state == ST_HUNT && !huntActive(now)) {     // target stopped transmitting
    if (!huntGoneAt) huntGoneAt = now;
    if (now - huntGoneAt > 2500) stopHunt();
  }
  if (state != ST_HUNT && huntType != H_NONE) {   // hunt was interrupted by another alert
    huntType = H_NONE;
    if (!attack) locked = false;
  }
  if (state == ST_SCAN) {                       // show each new threat once (most serious first)
    for (int i = 0; i < TH_COUNT; i++)
      if (th[i].active && !th[i].alerted) { thSel = i; state = ST_THREAT; stateStart = now; bannerOn = false; break; }
  }
  if (state == ST_SCAN) {                       // show each new evil twin once
    for (int i = 0; i < 4; i++)
      if (twins[i].used && !twins[i].shown && twinActive(twins[i], now)) { twinSel = i; state = ST_TWIN; stateStart = now; break; }
  }
  // "phone looking for <network>" banners, only on the radar screen
  if (state == ST_SCAN) {
    if (bannerOn && now - bannerStart > PROBE_SHOW_MS) bannerOn = false;
    if (!bannerOn && bnTail != bnHead) { curBanner = banners[bnTail]; bnTail = (bnTail + 1) & 7; bannerOn = true; bannerStart = now; }
  }

  // screen saver: any alert or other screen counts as activity
  if (state != ST_SCAN) lastActivity = now;
  bool wantDim = saverOn(now);
  if (wantDim != dimmed) { dimmed = wantDim; oled.dim(dimmed); }

  if (frameDue()) {
    oled.clearDisplay();
    switch (state) {
      case ST_BOOT:  drawBoot(now); break;
      case ST_ALERT: drawAlert(now); break;
      case ST_ENDED: drawEnded(now); break;
      case ST_TWIN:  drawTwin(now); break;
      case ST_TWINGONE: drawTwinGone(now); break;
      case ST_THREAT: drawThreat(now); break;
      case ST_HUNT:   drawHunt(now); break;
      default:
        if (saverOn(now)) drawSaver(now); else drawRadar(now);
        drawBanner(now);
        break;
    }
    oled.display();
  }
  yield();
}
