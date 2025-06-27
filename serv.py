import pywifi
from pywifi import const
import time

def scan_wifi():
    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]
    iface.scan()
    time.sleep(2)
    results = iface.scan_results()
    return results

def analyze_security(network):
    if network.akm:
        if const.AKM_TYPE_WPA2PSK in network.akm:
            return "WPA2-PSK"
        elif const.AKM_TYPE_WPAPSK in network.akm:
            return "WPA-PSK"
        elif const.AKM_TYPE_WPA3PSK in network.akm:
            return "WPA3-PSK"
        elif const.AKM_TYPE_NONE in network.akm:
            return "Open"
        else:
            return "Other"
    else:
        return "Open"

def main():
    print("Scanning for WiFi networks...")
    networks = scan_wifi()
    print(f"Found {len(networks)} networks.\n")
    print("{:<30}{:<15}{:<10}{:<10}".format("SSID", "Signal", "Security", "Hidden"))
    print("="*65)
    for net in networks:
        ssid = net.ssid
        signal = net.signal
        security = analyze_security(net)
        hidden = net.ssid == ""
        print("{:<30}{:<15}{:<10}{:<10}".format(ssid or "<Hidden>", signal, security, hidden))

if __name__ == "__main__":
    main()
