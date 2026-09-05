"""
AirSight-AI: Wireless Airspace Radar with Device & Vendor Identification
Transdisciplinary Project | Cyber Security & AI Edge Intelligence
- Modern Streamlit Fragment Architecture (@st.fragment):
    * Zero while True loop (eliminates StreamlitDuplicateElementId completely)
    * Zero full-page reloads (eliminates DOM blinking)
    * Real-time in-place diffing (preserves Plotly zoom & pan)
- Multi-protocol vendor fingerprinting & de-randomization
"""

import streamlit as st
import plotly.graph_objects as go
import time
import json

try:
    import serial
    import serial.tools.list_ports
    SERIAL_AVAILABLE = True
except ImportError:
    SERIAL_AVAILABLE = False

st.set_page_config(page_title="AirSight-AI: Wireless Airspace Radar", page_icon="🛡️", layout="wide")

# Theme styling matching original screenshot
st.markdown("""
<style>
    .stApp {
        background-color: #0b0f19;
        color: #e2e8f0;
    }
    .status-banner {
        background-color: #0d2818;
        border: 1px solid #1e5e3a;
        color: #4ade80;
        padding: 10px 16px;
        border-radius: 8px;
        font-size: 14px;
        font-weight: 500;
        display: flex;
        align-items: center;
        margin-bottom: 20px;
    }
    .metric-col {
        background-color: transparent;
        padding: 4px;
    }
    .metric-label {
        font-size: 13px;
        color: #94a3b8;
        font-weight: 500;
        margin-bottom: 2px;
    }
    .metric-value {
        font-size: 32px;
        font-weight: 600;
        color: #f8fafc;
    }
    .device-table-wrap {
        max-height: 480px;
        overflow-y: auto;
        border: 1px solid #1e293b;
        border-radius: 6px;
    }
    table.device-table {
        width: 100%;
        border-collapse: collapse;
        font-size: 12px;
        background-color: #0d1322;
        color: #cbd5e1;
    }
    table.device-table th {
        background-color: #111a2e;
        color: #94a3b8;
        padding: 8px 10px;
        text-align: left;
        position: sticky;
        top: 0;
        border-bottom: 1px solid #1e293b;
        font-weight: 600;
    }
    table.device-table td {
        padding: 6px 10px;
        border-bottom: 1px solid #162036;
        font-family: monospace;
    }
    table.device-table tr:hover {
        background-color: #162036;
    }
    .vendor-badge {
        display: inline-block;
        padding: 2px 6px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 600;
    }
    .empty-state {
        text-align: center;
        padding: 40px 20px;
        color: #64748b;
        font-size: 14px;
    }
</style>
""", unsafe_allow_html=True)

# Hardware OUI Manufacturer Database
KNOWN_OUIS = {
    # Apple
    "00:17:F2": "Apple", "F0:18:98": "Apple", "AC:BC:32": "Apple", "BC:D1:D3": "Apple",
    "DC:A9:04": "Apple", "70:EC:E4": "Apple", "A4:83:E7": "Apple", "34:E1:2D": "Apple",
    "F4:D4:88": "Apple", "14:7D:DA": "Apple", "28:CF:E9": "Apple", "3C:22:FB": "Apple",
    # Samsung
    "00:16:32": "Samsung", "00:12:FB": "Samsung", "00:26:37": "Samsung", "34:23:87": "Samsung",
    "88:32:9B": "Samsung", "50:01:D9": "Samsung", "A4:75:B9": "Samsung", "D8:90:E8": "Samsung",
    "CC:07:AB": "Samsung", "2C:59:8A": "Samsung", "08:EE:8B": "Samsung", "5C:51:88": "Samsung",
    # Xiaomi / Redmi / Poco
    "18:E8:29": "Xiaomi", "28:6C:07": "Xiaomi", "64:09:80": "Xiaomi", "74:23:44": "Xiaomi",
    "98:FA:E3": "Xiaomi", "F0:B4:29": "Xiaomi", "50:64:2B": "Xiaomi", "7C:49:EB": "Xiaomi",
    # OnePlus / Oppo / Realme
    "50:8A:06": "OnePlus / Oppo", "94:E9:79": "OnePlus / Oppo", "AC:C1:EE": "OnePlus / Oppo",
    "B4:0B:44": "OnePlus / Oppo", "DC:2B:66": "OnePlus / Oppo", "E4:AA:EC": "OnePlus / Oppo",
    # Vivo / iQOO
    "10:2A:B3": "Vivo", "5C:E8:EB": "Vivo", "90:00:4E": "Vivo", "E8:8D:28": "Vivo",
    # Google
    "00:1A:11": "Google Pixel", "3C:5A:37": "Google Pixel", "54:60:09": "Google Pixel", "F4:F5:D8": "Google Pixel",
    # Intel
    "A4:C3:F0": "Intel Corp", "00:1B:77": "Intel Corp", "00:21:6A": "Intel Corp", "34:13:E8": "Intel Corp",
    "68:05:71": "Intel Corp", "84:FD:D1": "Intel Corp", "9C:B6:D0": "Intel Corp",
    # Network Routers
    "C8:4B:D6": "TP-Link", "50:C7:BF": "TP-Link", "14:CC:20": "TP-Link", "00:31:92": "TP-Link",
    "00:E0:4C": "Realtek", "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi"
}

def resolve_vendor_name(mac: str, reported_vendor: str) -> str:
    if reported_vendor and reported_vendor not in ["Hardware Device", "Randomized Mobile", "Randomized Client", ""]:
        return reported_vendor
    prefix = mac[:8].upper()
    if prefix in KNOWN_OUIS:
        return KNOWN_OUIS[prefix]
    c = mac[1].upper() if len(mac) >= 2 else '0'
    if c in ['2', '6', 'A', 'E']:
        return "Randomized Mobile"
    return "Randomized / Other"

# State initialization
if "clusters" not in st.session_state:
    st.session_state.clusters = {}
if "mac_to_cluster" not in st.session_state:
    st.session_state.mac_to_cluster = {}
if "raw_devices" not in st.session_state:
    st.session_state.raw_devices = {}
if "serial_conn" not in st.session_state:
    st.session_state.serial_conn = None
if "cluster_counter" not in st.session_state:
    st.session_state.cluster_counter = 0

# --- Sidebar Controls ---
st.sidebar.title("⚙️ Controls")

detected_ports = []
if SERIAL_AVAILABLE:
    detected_ports = [p.device for p in serial.tools.list_ports.comports()]
if not detected_ports:
    detected_ports = ["No Ports Detected"]

selected_port = st.sidebar.selectbox("Select ESP32 COM Port", detected_ports, index=0)
start_scan = st.sidebar.toggle("▶️ Start Live Radar", value=True)

st.sidebar.markdown("---")
st.sidebar.subheader("Noise Filters")
min_rssi = st.sidebar.slider("Signal Cutoff (Min RSSI)", -95, -50, -75, help="Ignore weak signals from distant rooms/passersby")
expiry_seconds = st.sidebar.slider("Active Window (Device Timeout)", 15, 180, 45, help="Drop devices not heard from in X seconds")

table_view = st.sidebar.radio(
    "Table Display Mode:",
    ["Physical Devices (AI Mapped)", "All Raw Ephemeral MACs"],
    index=0
)

if st.sidebar.button("🧹 Clear Discovered Devices"):
    st.session_state.clusters = {}
    st.session_state.mac_to_cluster = {}
    st.session_state.raw_devices = {}
    st.session_state.cluster_counter = 0
    st.rerun()

# Serial Port Management
ser = st.session_state.serial_conn
if start_scan and selected_port != "No Ports Detected":
    if ser is None or not ser.is_open:
        try:
            ser = serial.Serial(selected_port, 115200, timeout=0.1)
            st.session_state.serial_conn = ser
        except Exception:
            ser = None
elif not start_scan and ser and ser.is_open:
    ser.close()
    st.session_state.serial_conn = None

def calculate_distance(rssi):
    return max(0.2, round(10.0 ** ((-45.0 - float(rssi)) / 24.0), 2))

# Header (Static once, never blinks)
st.title("🛡️ AirSight-AI: Wireless Airspace Radar")
st.caption("Transdisciplinary Project | Cyber Security & AI Edge Intelligence (Vendor Discovery Active)")

run_stream = start_scan and ser and ser.is_open

# --- Isolated Real-Time Fragment Function ---
# In modern Streamlit, decorating with @st.fragment natively isolates updates:
# 1. No full page reloads.
# 2. No while True loop -> zero StreamlitDuplicateElementId errors.
# 3. Persistent Plotly zoom & pan via uirevision.

def render_feed():
    now_ts = time.time()
    new_incoming = []

    if ser and ser.is_open:
        while ser.in_waiting > 0:
            try:
                line = ser.readline().decode('utf-8', errors='ignore').strip()
                if line.startswith("{") and line.endswith("}"):
                    item = json.loads(line)
                    new_incoming.append(item)
            except Exception:
                pass

    for pkt in new_incoming:
        m = pkt.get("mac")
        if not m:
            continue
        rssi = pkt.get("rssi", -70)
        if rssi < min_rssi:
            continue

        ch = pkt.get("ch", 1)
        ftype = pkt.get("type", "DATA")
        seq = pkt.get("seq", 0)
        sig = pkt.get("sig", "00000000")
        raw_vendor = pkt.get("vendor", "")
        vendor = resolve_vendor_name(m, raw_vendor)
        dist = calculate_distance(rssi)

        if m not in st.session_state.raw_devices:
            st.session_state.raw_devices[m] = {
                "mac": m, "vendor": vendor, "type": ftype, "rssi": rssi,
                "dist": dist, "ch": ch, "seq": seq, "sig": sig, "count": 1, "last_ts": now_ts
            }
        else:
            st.session_state.raw_devices[m].update({
                "vendor": vendor if vendor != "Randomized Mobile" else st.session_state.raw_devices[m]["vendor"],
                "rssi": rssi, "dist": dist, "ch": ch, "seq": seq,
                "count": st.session_state.raw_devices[m]["count"] + 1, "last_ts": now_ts
            })

        # De-randomization Clustering
        if m in st.session_state.mac_to_cluster:
            c_id = st.session_state.mac_to_cluster[m]
            if c_id in st.session_state.clusters:
                cl = st.session_state.clusters[c_id]
                cl["avg_rssi"] = round(0.7 * cl["avg_rssi"] + 0.3 * rssi, 1)
                cl["dist"] = calculate_distance(cl["avg_rssi"])
                cl["last_seq"] = seq
                cl["last_ts"] = now_ts
                cl["active_mac"] = m
                cl["count"] += 1
                cl["ch"] = ch
                cl["type"] = ftype
                if vendor != "Randomized Mobile" and cl["vendor"] in ["Randomized Mobile", "Unknown"]:
                    cl["vendor"] = vendor
        else:
            matched_c_id = None
            if sig != "00000000":
                for cid, cl in st.session_state.clusters.items():
                    if cl["sig"] == sig:
                        rssi_diff = abs(cl["avg_rssi"] - rssi)
                        seq_delta = (seq - cl["last_seq"]) % 4096
                        time_delta = now_ts - cl["last_ts"]
                        is_simul = time_delta < 0.5 and cl["active_mac"] != m

                        if rssi_diff <= 8.0 and seq_delta < 400 and not is_simul:
                            matched_c_id = cid
                            break

            if matched_c_id is not None:
                cl = st.session_state.clusters[matched_c_id]
                cl["macs"].add(m)
                cl["active_mac"] = m
                cl["avg_rssi"] = round(0.6 * cl["avg_rssi"] + 0.4 * rssi, 1)
                cl["dist"] = calculate_distance(cl["avg_rssi"])
                cl["last_seq"] = seq
                cl["last_ts"] = now_ts
                cl["count"] += 1
                cl["ch"] = ch
                cl["type"] = ftype
                if vendor != "Randomized Mobile" and cl["vendor"] in ["Randomized Mobile", "Unknown"]:
                    cl["vendor"] = vendor
                st.session_state.mac_to_cluster[m] = matched_c_id
            else:
                st.session_state.cluster_counter += 1
                new_cid = f"Device #{st.session_state.cluster_counter}"
                st.session_state.clusters[new_cid] = {
                    "id": new_cid, "vendor": vendor, "sig": sig, "macs": {m},
                    "active_mac": m, "avg_rssi": float(rssi), "dist": dist,
                    "last_seq": seq, "last_ts": now_ts, "count": 1, "ch": ch, "type": ftype
                }
                st.session_state.mac_to_cluster[m] = new_cid

    # Stale device timeout pruning
    stale_clusters = [cid for cid, cl in st.session_state.clusters.items() if now_ts - cl["last_ts"] > expiry_seconds]
    for cid in stale_clusters:
        for m in list(st.session_state.clusters[cid]["macs"]):
            st.session_state.mac_to_cluster.pop(m, None)
        st.session_state.clusters.pop(cid, None)

    stale_raw = [m for m, r in st.session_state.raw_devices.items() if now_ts - r["last_ts"] > expiry_seconds]
    for m in stale_raw:
        st.session_state.raw_devices.pop(m, None)

    active_clusters = list(st.session_state.clusters.values())
    active_raw = list(st.session_state.raw_devices.values())

    # Status Banner
    st_msg = f"🟢 Connected to {selected_port} — {len(active_clusters)} Physical Devices Active (Noise Filter &gt; {min_rssi} dBm)" if run_stream else f"🟡 Scanner Paused or Awaiting Port ({selected_port})"
    st.markdown(f'<div class="status-banner">{st_msg}</div>', unsafe_allow_html=True)

    # 4 KPI Metrics
    k1, k2, k3, k4 = st.columns(4)
    with k1:
        st.markdown(f'<div class="metric-col"><div class="metric-label">Physical Devices</div><div class="metric-value">{len(active_clusters)}</div></div>', unsafe_allow_html=True)
    with k2:
        st.markdown(f'<div class="metric-col"><div class="metric-label">Rotated MACs Caught</div><div class="metric-value">{len(active_raw)}</div></div>', unsafe_allow_html=True)
    with k3:
        st.markdown(f'<div class="metric-col"><div class="metric-label">Searching (Probe)</div><div class="metric-value">{len([c for c in active_clusters if "PROBE" in c["type"]])}</div></div>', unsafe_allow_html=True)
    with k4:
        st.markdown(f'<div class="metric-col"><div class="metric-label">Close Proximity (&lt;3m)</div><div class="metric-value">{len([c for c in active_clusters if c["dist"] < 3.0])}</div></div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Visuals: Scatter Plot on Left, Table on Right
    c_left, c_right = st.columns([1.1, 1.3])

    with c_left:
        st.subheader("📡 Live Signal & Distance Radar")
        st.caption("💡 Tip: Scroll to zoom, click and drag to pan. Double-click to reset zoom.")

        fig = go.Figure()
        if active_clusters:
            dists = [c["dist"] for c in active_clusters]
            rssis = [c["avg_rssi"] for c in active_clusters]
            sizes = [min(28, max(12, 10 + len(c["macs"]) * 2)) for c in active_clusters]
            labels = [f"<b>{c['id']} ({c['vendor']})</b><br>MAC: {c['active_mac']}<br>Sig: {c['sig']}<br>Rotated MACs: {len(c['macs'])}<br>Dist: {c['dist']}m ({c['avg_rssi']} dBm)" for c in active_clusters]

            fig.add_trace(go.Scatter(
                x=dists, y=rssis, mode='markers+text',
                text=[f"{c['vendor']}" if c['vendor'] != "Randomized Mobile" else c['id'] for c in active_clusters],
                textposition="top right",
                marker=dict(size=sizes, color='#60a5fa', opacity=0.82, line=dict(width=1.5, color='#93c5fd')),
                textfont=dict(color="#f8fafc", size=10), hovertext=labels, hoverinfo='text', name='Active Devices'
            ))

        fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="#0b0f19",
            plot_bgcolor="#0b0f19",
            uirevision="airsight_radar_zoom", # PRESERVES USER ZOOM & PAN!
            xaxis=dict(title="Est. Distance (m)", range=[0, 160], gridcolor="#1e293b", color="#94a3b8"),
            yaxis=dict(title="Signal Strength (dBm)", range=[-105, -15], gridcolor="#1e293b", color="#94a3b8"),
            showlegend=False,
            height=480,
            margin=dict(l=40, r=20, t=10, b=40)
        )

        st.plotly_chart(
            fig,
            use_container_width=True,
            config={"scrollZoom": True, "displayModeBar": True}
        )

    with c_right:
        st.subheader(f"📋 {table_view}")
        if table_view == "Physical Devices (AI Mapped)":
            if active_clusters:
                sorted_c = sorted(active_clusters, key=lambda x: x["dist"])
                rows = []
                for c in sorted_c:
                    badge_style = "background:#1e3a8a; color:#93c5fd;" if "Apple" in c["vendor"] else ("background:#14532d; color:#86efac;" if "Samsung" in c["vendor"] else "background:#334155; color:#cbd5e1;")
                    rows.append(
                        f"<tr>"
                        f"<td><b>{c['id']}</b></td>"
                        f"<td><span class='vendor-badge' style='{badge_style}'>{c['vendor']}</span></td>"
                        f"<td>{c['active_mac']}</td>"
                        f"<td><span style='color:#38bdf8;'>{len(c['macs'])} MACs</span></td>"
                        f"<td>{c['sig']}</td>"
                        f"<td>{c['avg_rssi']}</td>"
                        f"<td>{c['dist']}</td>"
                        f"</tr>"
                    )
                html = '<div class="device-table-wrap"><table class="device-table"><thead><tr><th>Device ID</th><th>Vendor / Brand</th><th>Active MAC</th><th>Rotations</th><th>Signature</th><th>RSSI</th><th>Dist (m)</th></tr></thead><tbody>' + "".join(rows) + '</tbody></table></div>'
                st.markdown(html, unsafe_allow_html=True)
            else:
                st.markdown('<div class="device-table-wrap"><div class="empty-state">📡 No active devices within signal threshold.<br>Adjust the RSSI slider if needed.</div></div>', unsafe_allow_html=True)
        else:
            if active_raw:
                sorted_r = sorted(active_raw, key=lambda x: x["dist"])
                rows = [f"<tr><td>{r['mac']}</td><td>{r['vendor']}</td><td>{st.session_state.mac_to_cluster.get(r['mac'], 'Mapped')}</td><td>{r['type']}</td><td>{r['rssi']}</td><td>{r['dist']}</td><td>{r['ch']}</td></tr>" for r in sorted_r]
                html = '<div class="device-table-wrap"><table class="device-table"><thead><tr><th>MAC Address</th><th>Vendor</th><th>Cluster</th><th>Type</th><th>RSSI</th><th>Dist (m)</th><th>Chan</th></tr></thead><tbody>' + "".join(rows) + '</tbody></table></div>'
                st.markdown(html, unsafe_allow_html=True)
            else:
                st.markdown('<div class="device-table-wrap"><div class="empty-state">📡 No packets detected above cutoff threshold.</div></div>', unsafe_allow_html=True)


# Execute using Streamlit Fragment (if available, updates without page reloads)
if hasattr(st, "fragment"):
    @st.fragment(run_every=1.5 if run_stream else None)
    def live_radar_fragment():
        render_feed()

    live_radar_fragment()
else:
    render_feed()
    if run_stream:
        time.sleep(1.2)
        st.rerun()
