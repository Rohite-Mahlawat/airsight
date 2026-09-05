# 🛡️ AirSight-AI: Real-Time Wireless Airspace Radar & Device De-Randomization

> **A 100% passive, listen-only RF airspace radar designed for sensitive environments (examination centers, secure corporate facilities, and data centers). Detects and tracks 2.4 GHz Wi-Fi transmitters and passive signals.**

---

## 📌 Project Overview

Traditional electronic security systems rely on either active network associations (which miss disconnected or searching mobile devices) or illegal radio frequency jammers. Active jamming creates dangerous side effects and legal issues.

**AirSight-AI** solves this challenge through a **100% passive, listen-only sensor architecture**:
1. **Zero RF Emissions:** Operates in strict promiscuous listen-only mode. It sends no handshakes, transmits no packets, and complies fully with wireless radio regulations.
2. **Promiscuous 802.11 Frame Interception:** Continuously hops across 2.4 GHz channels 1–13, passively capturing 802.11 management frames (Probe Requests, Beacons) and data frames.
3. **AI Hardware De-Randomization:** Solves modern mobile OS MAC randomization (iOS & Android) by correlating Information Element (IE) hardware capabilities, sequence number continuity, and spatial RF features.
4. **Log-Distance Path Loss Modeling:** Accurately estimates device distance and flags unauthorized devices entering a configurable immediate proximity threat zone (<3m).
5. **Real-Time Interactive Radar:** Displays airspace occupancy on an interactive dark-themed dashboard with persistent zoom/pan and manufacturer identification.

---

## 🏗️ System Architecture

```text
+------------------------------------+             +-----------------------------------------+
|        ESP32 Sensor Node           |             |           AirSight-AI Dashboard         |
|                                    |             |                                         |
| • 802.11 Promiscuous RX Sniffer    |   USB/UART  | • PySerial Ingestion Pipeline           |
| • Automatic Channel Hopping (1-13) | ==========> | • Multi-Feature De-Randomization Engine |
| • Hardware IE Fingerprint Hashing  | 115200 Baud | • Log-Distance Path Loss Distance Model |
| • Sequence & OUI Tag Extraction    |             | • Interactive Plotly Radar & UI         |
+------------------------------------+             +-----------------------------------------+
```

---

## 🧠 Scientific & Mathematical Models

### 1. Log-Distance Path Loss Distance Model
Physical distance from the sensor node is estimated using the logarithmic attenuation model:

$$d = 10^{\frac{P_0 - \text{RSSI}}{10n}}$$

Where:
* $P_0 = -45\text{ dBm}$ (Empirically calibrated received signal strength at a 1-meter reference distance).
* $10n = 24.0$ ($n = 2.4$, standard indoor radio propagation exponent).
* $\text{RSSI}$ is the instantaneous signal strength captured by the ESP32 transceiver.

### 2. Multi-Factor Device De-Randomization
To defeat ephemeral MAC rotation without deanonymizing personal user data:
* **Information Elements (IE) Signature:** Hashes the exact combination and ordering of 802.11 capability tags (Supported Rates, HT/VHT capabilities, Vendor tags). Because these represent physical radio capabilities, they remain invariant across MAC rotations.
* **Sequence Trajectory ($\Delta \text{Seq}$):** Tracks the monotonic increment of the 12-bit hardware baseband counter (`seqctl >> 4`).
* **Spatio-Temporal Gating:** Separates identical co-located devices by checking for simultaneous packet transmission within a 500 ms collision window.

---

## 📁 Repository Structure

```text
airsight/
├── airsight/
│   └── airsight.ino       # ESP32 C++ promiscuous sniffer firmware
├── app.py                 # Streamlit real-time radar dashboard
├── requirements.txt       # Python dependencies
├── .gitignore             # Git ignore rules
└── README.md              # Project documentation
```

---

## 🚀 Quickstart Guide

### 1. Hardware Requirements
* **Microcontroller:** ESP32 Development Board (38-pin or 30-pin, 2.4 GHz Wi-Fi)
* **Connection:** Micro-USB / USB-C data cable
* **Host PC:** Windows, Linux (Kali/Ubuntu), or macOS

### 2. Flash the ESP32 Firmware
1. Open the Arduino IDE.
2. Open `airsight/airsight.ino`.
3. Under **Tools > Board**, select **ESP32 Dev Module**.
4. Select your serial port under **Tools > Port**.
5. Set upload speed to **921600** (or **115200**).
6. Click **Upload**.
7. Close the Arduino Serial Monitor once flashing completes.

### 3. Run the Dashboard
1. Clone this repository:
   ```bash
   git clone https://github.com/Rohite-Mahlawat/airsight.git
   cd airsight
   ```
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Launch the dashboard:
   ```bash
   streamlit run app.py
   ```
4. In the browser interface (`http://localhost:8501`), select your ESP32 COM port and toggle **Start Live Radar**.

---
