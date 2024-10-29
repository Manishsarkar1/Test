import scapy.all as scapy

def scan(ip_range):
    arp_request = scapy.ARP(pdst = ip_range)
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout = 1, verbose = False)[0]

    devices = []
    for element in answered_list:
        device_info = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        devices.append(device_info)

    return devices

ip_range = input("Enter the ip you want to scan-> ")
devices = scan(ip_range)
print("Devices found:")
for device in devices:
    print(f"IP: {device['ip']}, MAC: {device['mac']}")
