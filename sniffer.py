import logging
import threading
import time
from scapy.all import conf, get_if_hwaddr, sendp, sniff
from scapy.layers.l2 import Ether
from scapy.layers.ppp import PPP, PPPoED, PPPoE, PPPoETag

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class PPPoESniffer(threading.Thread):
    def __init__(self, interface, callback=None):
        super().__init__()
        self.interface = interface
        self.callback = callback  # Callback function to send status updates and credentials to GUI
        self.running = False
        self.session_id = 0x1234
        self.local_mac = None
        self.client_mac = None
        self.lcp_configured_client = False
        self.lcp_configured_server = False
        self.credentials_found = False

        # Configure scapy interface
        conf.iface = interface

    def log(self, message, level="info"):
        if level == "info":
            logging.info(message)
        elif level == "warning":
            logging.warning(message)
        elif level == "error":
            logging.error(message)
            
        if self.callback:
            self.callback({"type": "log", "message": message, "level": level})

    def log_event(self, key, level="info", **kwargs):
        msg = f"[{level.upper()}] {key} ({kwargs})"
        if level == "info":
            logging.info(msg)
        elif level == "warning":
            logging.warning(msg)
        elif level == "error":
            logging.error(msg)
            
        if self.callback:
            self.callback({"type": "log_event", "key": key, "level": level, "kwargs": kwargs})

    def run(self):
        self.running = True
        try:
            self.local_mac = get_if_hwaddr(self.interface)
            self.log_event("log_listening_start", desc=f"{self.interface} ({self.local_mac})")
            self.log_event("log_ready_wait")
        except Exception as e:
            self.log_event("log_err_mac", level="error", err=str(e))
            self.running = False
            return

        # Start sniffing
        while self.running and not self.credentials_found:
            try:
                sniff(
                    iface=self.interface,
                    prn=self.handle_packet,
                    filter="ether proto 0x8863 or ether proto 0x8864",
                    timeout=1,
                    store=0
                )
            except Exception as e:
                self.log_event("log_err_sniff", level="error", err=str(e))
                time.sleep(1)

    def stop_sniffer(self):
        self.running = False
        self.log_event("log_listening_stop")

    def handle_packet(self, pkt):
        if not self.running or self.credentials_found:
            return

        # 1. Handle PPPoE Discovery (0x8863)
        if pkt.haslayer(PPPoED):
            pppoed = pkt[PPPoED]
            self.client_mac = pkt[Ether].src

            # PADI (Active Discovery Initiation) -> Send PADO
            if pppoed.code == 0x09:
                self.log_event("log_padi", mac=self.client_mac)
                
                # Extract Host-Uniq tag if present to echo it back
                host_uniq = None
                if hasattr(pppoed, "tag_list"):
                    for tag in pppoed.tag_list:
                        if tag.tag_type == 0x0103:  # Host-Uniq
                            host_uniq = tag

                # Construct PADO (Offer)
                pado = Ether(dst=self.client_mac, src=self.local_mac, type=0x8863) / \
                       PPPoED(code=0x07, sessionid=0) / \
                       PPPoETag(tag_type="Service-Name", tag_value="") / \
                       PPPoETag(tag_type="AC-Name", tag_value="Fiber_Router_Fake_AC")
                
                if host_uniq:
                    pado = pado / PPPoETag(tag_type="Host-Uniq", tag_value=host_uniq.tag_value)
                
                sendp(pado, iface=self.interface, verbose=False)
                self.log_event("log_pado")

            # PADR (Active Discovery Request) -> Send PADS
            elif pppoed.code == 0x19:
                self.log_event("log_padr", mac=self.client_mac)
                
                # Extract Host-Uniq
                host_uniq = None
                if hasattr(pppoed, "tag_list"):
                    for tag in pppoed.tag_list:
                        if tag.tag_type == 0x0103:
                            host_uniq = tag

                pads = Ether(dst=self.client_mac, src=self.local_mac, type=0x8863) / \
                       PPPoED(code=0x65, sessionid=self.session_id) / \
                       PPPoETag(tag_type="Service-Name", tag_value="")
                
                if host_uniq:
                    pads = pads / PPPoETag(tag_type="Host-Uniq", tag_value=host_uniq.tag_value)
                
                sendp(pads, iface=self.interface, verbose=False)
                self.log_event("log_pads", session_id=hex(self.session_id))

        # 2. Handle PPPoE Session (0x8864)
        elif pkt.haslayer(PPPoE):
            pppoes = pkt[PPPoE]
            
            # Ensure it is a PPP packet
            if pkt.haslayer(PPP):
                ppp = pkt[PPP]
                
                # PPP Protocol: 0xc021 (LCP)
                if ppp.proto == 0xc021:
                    self.handle_lcp(pkt)
                
                # PPP Protocol: 0xc023 (PAP)
                elif ppp.proto == 0xc023:
                    self.handle_pap(pkt)

    def handle_lcp(self, pkt):
        # PPPoE -> PPP -> LCP Raw Payload processing
        # LCP Code: 1 (Configure-Request), 2 (Configure-Ack), 3 (Configure-Nak), 4 (Configure-Reject), 5 (Terminate-Request)
        payload = bytes(pkt[PPP].payload)
        if len(payload) < 4:
            return
            
        lcp_code = payload[0]
        lcp_id = payload[1]
        lcp_len = int.from_bytes(payload[2:4], byteorder='big')
        lcp_data = payload[4:lcp_len]

        if lcp_code == 1:
            # Modem is requesting LCP configuration.
            # We automatically acknowledge their request (Configure-Ack)
            self.log_event("log_lcp_req")
            
            # Send Configure-Ack matching the payload exactly
            ack = Ether(dst=self.client_mac, src=self.local_mac, type=0x8864) / \
                  PPPoE(sessionid=self.session_id) / \
                  PPP(proto=0xc021) / \
                  bytes([2, lcp_id]) / payload[2:lcp_len]
                  
            sendp(ack, iface=self.interface, verbose=False)
            self.log_event("log_lcp_ack")
            self.lcp_configured_client = True

            # Send our LCP Configure-Request, requesting PAP Authentication (0xc023)
            # Option 3 (Authentication Protocol), Length 4, Protocol 0xc023 (PAP)
            pap_req = Ether(dst=self.client_mac, src=self.local_mac, type=0x8864) / \
                      PPPoE(sessionid=self.session_id) / \
                      PPP(proto=0xc021) / \
                      bytes([1, 1, 0, 8, 3, 4, 192, 35]) # Code 1, ID 1, Len 8, Type 3, Len 4, Proto PAP (192, 35 / 0xc023)
            
            sendp(pap_req, iface=self.interface, verbose=False)
            self.log_event("log_lcp_pap")

        elif lcp_code == 2:
            # Modem acknowledged our LCP request
            self.log_event("log_lcp_pap_ack")
            self.lcp_configured_server = True
            
        elif lcp_code == 3 or lcp_code == 4:
            self.log_event("log_lcp_pap_nak", level="warning")
            # Force PAP again
            pap_req = Ether(dst=self.client_mac, src=self.local_mac, type=0x8864) / \
                      PPPoE(sessionid=self.session_id) / \
                      PPP(proto=0xc021) / \
                      bytes([1, 2, 0, 8, 3, 4, 192, 35])
            sendp(pap_req, iface=self.interface, verbose=False)

    def handle_pap(self, pkt):
        payload = bytes(pkt[PPP].payload)
        if len(payload) < 4:
            return
            
        pap_code = payload[0]
        pap_id = payload[1]
        
        # PAP Code 1: Authenticate-Request
        if pap_code == 1:
            try:
                # Format: Code (1) + ID (1) + Length (2) + Peer-ID Length (1) + Peer-ID + Password Length (1) + Password
                peer_id_len = payload[4]
                peer_id = payload[5:5+peer_id_len].decode('utf-8', errors='ignore')
                
                pass_len_offset = 5 + peer_id_len
                pass_len = payload[pass_len_offset]
                password = payload[pass_len_offset+1:pass_len_offset+1+pass_len].decode('utf-8', errors='ignore')
                
                self.log_event("log_success")
                self.log_event("log_user", user=peer_id)
                self.log_event("log_pass", password=password)
                
                self.credentials_found = True
                self.running = False
                
                # Send Success Response to client so it doesn't keep retrying immediately
                # PAP Code 2: Authenticate-Ack
                pap_ack = Ether(dst=self.client_mac, src=self.local_mac, type=0x8864) / \
                          PPPoE(sessionid=self.session_id) / \
                          PPP(proto=0xc023) / \
                          bytes([2, pap_id, 0, 5, 0]) # Code 2, ID, Len 5, Msg Len 0
                sendp(pap_ack, iface=self.interface, verbose=False)
                
                if self.callback:
                    self.callback({
                        "type": "credentials",
                        "username": peer_id,
                        "password": password
                    })
            except Exception as e:
                self.log_event("log_pap_err", level="error", err=str(e))
