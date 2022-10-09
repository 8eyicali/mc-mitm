# <div align="center">Some WPA2 and WPA3 Attacks</div>

<a id="intro"></a>
# 1. Introduction

The Attacks use the Python implementation of a Multi-Channel Machine-in-the-Middle (MC-MitM) position.
Beacons with Channel Switch Announcement (CSA) elements are spoofed to obtain this MitM position.
The goal of this code is to more rapidly proto-type and practically confirm attacks that require
a multi-channel MitM position.


<a id="id-prerequisites"></a>
# 2. Prerequisites

The test tool was tested on Ubuntu 22.04. To install the required dependencies, execute:

	# Ubuntu:
	sudo apt-get update
	sudo apt-get install libnl-3-dev libnl-genl-3-dev libnl-route-3-dev libssl-dev \
		libdbus-1-dev git pkg-config build-essential macchanger net-tools virtualenv \
		rfkill hostapd

Then clone this repository **and its submodules**:

	git clone https://github.com/8eyicali/some_WPA2_WPA3_attacks.git --recursive
	cd some_WPA2_WPA3_attacks

Now build the tools and configure a virtual python3 environment:

	# Build modified Hostapd
	cd research
	./build.sh

	# Configure python environment
	./pysetup.sh

The above instructions only have to be executed once. After pulling in new code assure that
any submodules are updated be executing `git submodule update`. Remember to also recompile
the modified Hostapd after pulling in new code.


<a id="launch-attack"></a>
# 3. Launching the attacks

The attack **requires two wireless network cards** and you must be within radio distance of both
the client and the AP. The most reliable network card is one based on [`ath9k_htc`](https://wikidevi.wi-cat.ru/Ath9k_htc).
An example is a [Technoethical N150 HGA](https://tehnoetic.com/tet-n150hga). You can also use
`mac80211_hwsim` on Linux to use this script with simulated interfaces.


## 3.1. Starting the Attacks

Every time you want to use the test tool, you first have to load the virtual python environment
as root. This can be done using:

	cd research
	sudo su
	source venv/bin/activate

You should now disable Wi-Fi in your network manager so it will not interfere with the test tool.

There are two possible attacks:

### 3.1.1. WPA2 Downgrade-Attack to force use of RC4

This is a Downgrade-Attack based on the mc-mitm.py implementation. Here an Access Point (AP) which supports CCMP and TKIP will be cloned on another channel only supporting TKIP. All Beacons from the real AP will be modified so that only TKIP is advertised. This tool tests whether a device connects to the AP using TKIP and performs the first three messages of the 4-way handshake. If the attack succeeds the Group Temporal Key (GTK) will be encrypted with RC4 during the third handshake message. This attack is based on the research paper "Predicting, Decrypting, and Abusing WPA2/802.11 Group Keys" from Mathy Vanhoef and Frank Piessens.

You can then start the attack:

	./downgradeRC4.py wlan1 wlan2 testnetwork --target 00:11:11:11:11:11 --continuous-csa

The parameters are as follows:

- `wlan1`: this is the wireless network card that will listen to traffic on the channel of the target (real) AP.

- `wlan2`: this is the wireless network card that will advertise a rogue clone of the target AP on a different channel.

- `testnetwork`: this is the SSID of the Wi-Fi network we are targetting.

- `--target`: this parameter can be used to target a single client. This is strongly recommended because
  targeting only one client drastically improves the reliability of the attack.

- `--continuous-csa`: this means beacons with CSA elements will be continuously spoofed in the channel
  containing the real AP. This improves the change that any target client will move to the rogue channel.

You can execute the script before or after the targeted client connects to the network. If you want
to intercept or target the connection process you have to start the script first and then connect
with the target client to the network. Otherwise, when targeting data frames, you can first start the
client and afterwards start the script. The script will output **"Established MitM position against client"**
in green when the machine-in-the-middle position has been successfully established.

Optional arguments:

- `--debug`: output extra debugging information.

### 3.1.2. Attacking SAE's Group Negotiation

This tool tests which SAE Groups a device chooses while connecting to a WPA3-Access Point (AP). A WPA3-AP is being setup using hostapd. The AP rejects all SAE groups a device chooses while connecting to test if and which alternative groups it chooses. The chosen groups can be used for potential Downgrade- or Denial-of-Service Attacks. The idea is based on the research paper "Dragonblood: Analyzing the Dragonfly Handshake of WPA3 and EAP-pwd" from Mathy Vanhoef and Eyal Ronen.

You can then start the attack:

	./attackSaeGroupNegotiation.py ssid interface_AP interface_inject

The parameters are as follows:

- `ssid`: this is the SSID of the WPA3-AP you would like to set up, it can be anything

- `interface_AP`: this is the wireless network card that will advertise a WPA3-AP, make sure the wireless network card is compatible with WPA3

- `interface_inject`: this is the wireless network card that will sniff and inject commit-frames

