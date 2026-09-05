/*
 * AirSight-AI: 802.11 Passive Sniffer + Hardware Vendor Fingerprinting
 * Platform: ESP32 (38-pin / 30-pin Dev Board)
 * 100% Passive Promiscuous Mode with Channel Hopping (1-13)
 * Features:
 *   - Extracts Vendor OUI from Vendor-Specific IEs (ID 221) even when MAC is randomized!
 *   - Identifies Apple, Samsung, Qualcomm (Xiaomi/OnePlus), MediaTek (Vivo/Oppo), etc.
 *   - Size: ~245 KB (Compiles effortlessly on default partition)
 */

#include <WiFi.h>
#include "esp_wifi.h"

#define SERIAL_BAUD 115200
#define HOP_INTERVAL_MS 250

uint8_t currentChannel = 1;
unsigned long lastHopTime = 0;

typedef struct {
  int16_t fctl;
  int16_t duration;
  uint8_t da[6]; // Destination Address
  uint8_t sa[6]; // Source Address / Transmitter
  uint8_t bssid[6];
  int16_t seqctl;
} __attribute__((packed)) WifiMacHeader;

// FNV-1a hash of 802.11 Information Elements (Hardware Signature)
uint32_t compute_ie_signature(const uint8_t* payload, int len) {
  uint32_t hash = 2166136261u;
  if (len <= sizeof(WifiMacHeader)) return 0;

  int offset = sizeof(WifiMacHeader);
  while (offset + 1 < len) {
    uint8_t id = payload[offset];
    uint8_t ie_len = payload[offset + 1];
    if (offset + 2 + ie_len > len) break;

    hash ^= id;
    hash *= 16777619u;

    if (id == 1 || id == 45 || id == 50 || id == 127 || id == 191 || id == 221) {
      for (int b = 0; b < ie_len && b < 12; ++b) {
        hash ^= payload[offset + 2 + b];
        hash *= 16777619u;
      }
    }
    offset += 2 + ie_len;
  }
  return hash;
}

// Extract Vendor name from Vendor-Specific IE tags (even with randomized MACs)
void detect_vendor(const uint8_t* payload, int len, bool is_random, char* out_vendor, size_t max_len) {
  if (len > sizeof(WifiMacHeader)) {
    int offset = sizeof(WifiMacHeader);
    while (offset + 4 < len) {
      uint8_t id = payload[offset];
      uint8_t ie_len = payload[offset + 1];
      if (offset + 2 + ie_len > len) break;

      // Element ID 221 (0xDD) is Vendor Specific IE
      if (id == 221 && ie_len >= 3) {
        uint8_t v0 = payload[offset + 2];
        uint8_t v1 = payload[offset + 3];
        uint8_t v2 = payload[offset + 4];

        if (v0 == 0x00 && v1 == 0x17 && v2 == 0xF2) {
          snprintf(out_vendor, max_len, "Apple (iOS)");
          return;
        } else if (v0 == 0x00 && v1 == 0x10 && v2 == 0x18) {
          snprintf(out_vendor, max_len, "Samsung / Broadcom");
          return;
        } else if (v0 == 0x00 && v1 == 0x03 && v2 == 0x7F) {
          snprintf(out_vendor, max_len, "Qualcomm (Android)");
          return;
        } else if (v0 == 0x00 && v1 == 0x0C && v2 == 0x43) {
          snprintf(out_vendor, max_len, "MediaTek (Android)");
          return;
        } else if (v0 == 0x50 && v1 == 0x6F && v2 == 0x9A) {
          snprintf(out_vendor, max_len, "Android (WFA P2P)");
          return;
        } else if (v0 == 0x00 && v1 == 0x50 && v2 == 0xF2) {
          snprintf(out_vendor, max_len, "Microsoft / WPS");
          return;
        }
      }
      offset += 2 + ie_len;
    }
  }

  if (is_random) {
    snprintf(out_vendor, max_len, "Randomized Mobile");
  } else {
    snprintf(out_vendor, max_len, "Hardware Device");
  }
}

void wifi_promiscuous_rx_callback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;

  const wifi_promiscuous_pkt_t *packet = (wifi_promiscuous_pkt_t*)buf;
  if (packet->rx_ctrl.sig_len < sizeof(WifiMacHeader)) return;

  const WifiMacHeader *header = (const WifiMacHeader*)packet->payload;

  // Filter multicast/broadcast MACs
  if (header->sa[0] & 0x01) return;
  if (header->sa[0] == 0x00 && header->sa[1] == 0x00 && header->sa[2] == 0x00) return;

  uint8_t frame_type = (header->fctl & 0x0C) >> 2;
  uint8_t frame_subtype = (header->fctl & 0xF0) >> 4;

  const char* type_str = "DATA";
  uint32_t signature = 0;
  bool is_random = (header->sa[0] & 0x02) != 0;
  char vendor[28] = "Hardware Device";

  if (frame_type == 0) {
    if (frame_subtype == 4) {
      type_str = "PROBE_REQ";
      signature = compute_ie_signature(packet->payload, packet->rx_ctrl.sig_len);
      detect_vendor(packet->payload, packet->rx_ctrl.sig_len, is_random, vendor, sizeof(vendor));
    } else if (frame_subtype == 8) {
      type_str = "BEACON";
      snprintf(vendor, sizeof(vendor), "Access Point");
    } else {
      type_str = "MGMT";
    }
  } else if (frame_type == 2) {
    type_str = "DATA";
    if (is_random) snprintf(vendor, sizeof(vendor), "Randomized Client");
  }

  // 12-bit sequence number
  uint16_t seq_num = (header->seqctl >> 4) & 0x0FFF;

  // 6-byte Source MAC (sa[0] through sa[5])
  char src_mac[18];
  snprintf(src_mac, sizeof(src_mac), "%02X:%02X:%02X:%02X:%02X:%02X",
           header->sa[0], header->sa[1], header->sa[2],
           header->sa[3], header->sa[4], header->sa[5]);

  // Output structured JSON line over Serial
  Serial.printf("{\"mac\":\"%s\",\"type\":\"%s\",\"vendor\":\"%s\",\"rssi\":%d,\"ch\":%d,\"seq\":%u,\"sig\":\"%08X\"}\n",
                src_mac, type_str, vendor, packet->rx_ctrl.rssi, packet->rx_ctrl.channel, seq_num, signature);
}

void setup() {
  Serial.begin(SERIAL_BAUD);
  delay(300);

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);

  wifi_promiscuous_filter_t filter = {
    .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA
  };
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(&wifi_promiscuous_rx_callback);
  esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
  esp_wifi_set_promiscuous(true);
}

void loop() {
  unsigned long now = millis();
  if (now - lastHopTime >= HOP_INTERVAL_MS) {
    lastHopTime = now;
    currentChannel++;
    if (currentChannel > 13) currentChannel = 1;
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
  }
}
