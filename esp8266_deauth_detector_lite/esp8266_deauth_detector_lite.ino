/*
  ============================================================
   ESP8266 Deauth Detector LITE  -  by Gamkers
  ============================================================
  Deauth detection only. Listens (receive only, never transmits) for WiFi
  deauthentication / disassociation frames, the frames used by "deauth"
  attacks that kick devices off a network. When a flood is seen it raises
  an alert and shows the MAC addresses involved.

  Board   : ESP8266 (NodeMCU 1.0 / LOLIN(WEMOS) D1 mini)
  Display : 0.96" SSD1306 OLED 128x64, I2C (0x3C)
  Wiring  : OLED SDA -> D1, SCL -> D2   (nothing else needed)
  Library : Adafruit SSD1306 + Adafruit GFX

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
#define SAVER_MS       180000   // screen saver after 3 minutes without alerts (0 = never)

// ================== TYPES ==================
enum AppState : uint8_t { ST_BOOT, ST_SCAN, ST_ALERT, ST_ENDED };

struct DeauthEvt { uint8_t src[6], dst[6], bss[6]; uint16_t reason; int8_t rssi; uint8_t ch; };
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

// ================== SNIFFER (runs inside the WiFi driver) ==================
volatile uint32_t pktCount = 0, deauthRaw = 0;
volatile uint8_t curCh = 1;
DeauthEvt evQ[16];
volatile uint8_t evHead = 0, evTail = 0;
MacEvt macQ[16];
volatile uint8_t mqHead = 0, mqTail = 0;

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
      evHead = nh;
    }
  } else if ((pktCount & 7) == 0) {    // sample normal traffic for the radar
    uint8_t nh = (mqHead + 1) & 15;
    if (nh != mqTail) {
      memcpy(macQ[mqHead].mac, f + 10, 6);
      macQ[mqHead].rssi = rssi;
      mqHead = nh;
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
uint16_t chLevel[CH_MAX + 1], chPeak[CH_MAX + 1];
uint32_t chDeauthAt[CH_MAX + 1];

Attacker att[8];
Contact ct[20];

bool attack = false;
uint32_t attackStart = 0, lastHot = 0, attackStartPkts = 0;
uint32_t endDur = 0, endPkts = 0;
uint32_t ledFlashUntil = 0, ledSeenDeauth = 0;
uint32_t lastActivity = 0;
bool dimmed = false;

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

void drainQueues(uint32_t now) {
  while (evTail != evHead) {
    DeauthEvt e = evQ[evTail];
    evTail = (evTail + 1) & 15;
    addAttacker(e, now);
    if (e.ch >= 1 && e.ch <= CH_MAX) chDeauthAt[e.ch] = now;
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
  endDur = now - attackStart;
  endPkts = deauthRaw - attackStartPkts;
  locked = false;
  state = ST_ENDED;
  stateStart = now;
  Serial.printf("[+] Attack ended: %lus, %lu frames\n", (unsigned long)(endDur / 1000), (unsigned long)endPkts);
}

void channelTick(uint32_t now) {
  if (now - lastHop < HOP_MS) return;
  uint32_t dt = now - lastHop;
  lastHop = now;
  uint32_t pc = pktCount, dc = deauthRaw;
  uint32_t dp = pc - hopPkt, dd = dc - hopDeauth;
  hopPkt = pc; hopDeauth = dc;
  chLevel[curCh] = dp;
  if (dp > chPeak[curCh]) chPeak[curCh] = dp;
  if (!locked) {
    if (dd > 0 && dd * 1000UL / imax(dt, 1) >= ATTACK_RATE) hot(now, curCh);   // flood on this channel
    else hopTo(curCh % CH_MAX + 1);
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
  for (int c = 1; c <= CH_MAX; c++) chPeak[c] = chPeak[c] * 9 / 10;
  for (int i = 0; i < 20; i++) if (ct[i].used && now - ct[i].last > 20000) ct[i].used = false;
  if (attack && now - lastHot > ATTACK_END_MS) endAttack(now);
}

void ledSet(bool on) { digitalWrite(LED_PIN, on ? LOW : HIGH); }   // built-in LED is on when LOW

void ledTick(uint32_t now) {
  uint32_t d = deauthRaw;
  if (d != ledSeenDeauth) { ledSeenDeauth = d; ledFlashUntil = now + 40; }   // flash on every deauth frame
  bool on;
  if (attack) on = (now / 80) % 2;                         // fast blink during attack
  else if (state == ST_ENDED) on = (now / 400) % 2;        // slow blink: attack just ended
  else on = (int32_t)(ledFlashUntil - now) > 0;
  ledSet(on);
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
  snprintf(b, sizeof b, "SCAN%.*s", dots, "...");
  txt(66, 0, b, 1, WH);
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
    txtC(44, "ATTACK ENDED", 1, WH);
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
  ledSet(false);
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
  Serial.println(F("Deauth detector LITE running (passive, receive only)"));
}

void loop() {
  uint32_t now = millis();

  drainQueues(now);
  channelTick(now);
  secondTick(now);
  ledTick(now);

  if (state == ST_BOOT && now - stateStart > BOOT_MS) state = ST_SCAN;
  if (state == ST_ENDED && now - stateStart > 4000) state = ST_SCAN;

  // screen saver: any alert counts as activity
  if (state != ST_SCAN) lastActivity = now;
  bool wantDim = saverOn(now);
  if (wantDim != dimmed) { dimmed = wantDim; oled.dim(dimmed); }

  if (frameDue()) {
    oled.clearDisplay();
    switch (state) {
      case ST_BOOT:  drawBoot(now); break;
      case ST_ALERT: drawAlert(now); break;
      case ST_ENDED: drawEnded(now); break;
      default:
        if (saverOn(now)) drawSaver(now); else drawRadar(now);
        break;
    }
    oled.display();
  }
  yield();
}
