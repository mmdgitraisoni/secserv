import pywifi
from pywifi import const
import time
import csv
import sys

# List of common default SSIDs (you can expand this list)
DEFAULT_SSIDS = [
    "linksys", "netgear", "dlink", "default", "tp-link", "asus", "belkin",
    "wifi", "home", "guest", "tplink", "xfinitywifi", "attwifi"
]

def scan_wifi():
    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]
    iface.scan()
    time.sleep(2)
    results = iface.scan_results()
    return results

def analyze_security(network):
    if network.akm:
        if const.AKM_TYPE_WPA3PSK in network.akm:
            return "WPA3-PSK"
        elif const.AKM_TYPE_WPA2PSK in network.akm:
            return "WPA2-PSK"
        elif const.AKM_TYPE_WPAPSK in network.akm:
            return "WPA-PSK"
        elif const.AKM_TYPE_NONE in network.akm:
            return "Open"
        else:
            return "Other"
    else:
        return "Open"

def is_default_ssid(ssid):
    ssid_lower = ssid.lower()
    for default in DEFAULT_SSIDS:
        if default in ssid_lower:
            return True
    return False

def highlight_security(security):
    if security == "Open":
        return "!! OPEN !!"
    elif security == "WPA-PSK":
        return "! WEAK !"
    elif security == "WPA2-PSK":
        return "OK"
    elif security == "WPA3-PSK":
        return "GOOD"
    else:
        return "UNKNOWN"

def main():
    print("Scanning for WiFi networks...")
    networks = scan_wifi()
    print(f"Found {len(networks)} networks.\n")

    # Prepare for CSV export
    csv_rows = []
    headers = [
        "SSID", "Signal", "Security", "Hidden", "Default_SSID", "Security_Flag"
    ]

    print("{:<30}{:<8}{:<12}{:<8}{:<14}{}".format(
        "SSID", "Signal", "Security", "Hidden", "Default_SSID", "Security_Flag"
    ))
    print("="*85)

    for net in networks:
        ssid = net.ssid or "<Hidden>"
        signal = net.signal
        security = analyze_security(net)
        hidden = (net.ssid == "")
        is_default = is_default_ssid(ssid)
        sec_flag = highlight_security(security)

        print("{:<30}{:<8}{:<12}{:<8}{:<14}{}".format(
            ssid, signal, security, str(hidden), str(is_default), sec_flag
        ))

        csv_rows.append([
            ssid, signal, security, hidden, is_default, sec_flag
        ])

    # Export to CSV
    out_filename = "wifi_security_report.csv"
    try:
        with open(out_filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(csv_rows)
        print(f"\nReport exported to {out_filename}")
    except Exception as e:
        print(f"Failed to write CSV: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
