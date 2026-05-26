import os
import sys
import threading
import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk
import urllib.request
import tempfile
import subprocess

# Enable high DPI scaling
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")  # Themes: "blue" (standard), "green", "dark-blue"

try:
    from scapy.all import get_working_ifaces
    from sniffer import PPPoESniffer
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

TRANSLATIONS = {
    "tr": {
        "window_title": "Fiber WAN Şifre Yakalayıcı - Designed by HamsoTR",
        "title": "FİBER WAN KİMLİK BİLGİSİ YAKALAYICI",
        "subtitle": "Fiber modemin WAN (PPPoE) kullanıcı adı ve şifresini bulma aracı",
        "label_iface": "1. Ağ Arayüzü Seçin (Ethernet Kartı)",
        "label_steps": "2. Bağlantı Yönergesi",
        "btn_refresh": "Kartları Yenile",
        "btn_npcap": "Npcap Sürücüsü Kur",
        "btn_start": "DİNLEMEYİ BAŞLAT",
        "btn_stop": "DİNLEMEYİ DURDUR",
        "label_captured": "🔑 YAKALANAN KİMLİK BİLGİLERİ",
        "label_username": "Kullanıcı Adı:",
        "label_password": "WAN Şifresi:  ",
        "btn_copy": "Kopyala",
        "label_log": "📋 SİSTEM GÜNLÜĞÜ",
        "instructions": (
            "YAKALAMA İŞLEMİ ADIMLARI:\n\n"
            "Adım 1: Fiber kutusundan (ONT) gelen sarı/siyah kabloyu modeminizden çıkarın.\n\n"
            "Adım 2: Modemin arkasındaki renkli WAN portunu, bir Ethernet kablosu ile bu bilgisayarın Ethernet portuna bağlayın.\n\n"
            "Adım 3: Yukarıdan bilgisayarınızın fiziksel Ethernet kartını seçin ve aşağıdaki 'Dinlemeyi Başlat' butonuna tıklayın.\n\n"
            "Adım 4: Fiber modeminizi arkasındaki güç düğmesinden kapatın ve tekrar açın (veya güç kablosunu çıkarıp takın).\n\n"
            "Modem açılırken bilgisayarınıza PPPoE istekleri gönderecek ve şifreniz sağ tarafta otomatik belirecektir!"
        ),
        "log_checking": "Sistem denetleniyor...",
        "log_ready": "Gerekli sürücüler (Npcap/WinPcap) hazır.",
        "log_no_npcap": "UYARI: Npcap sürücüsü sisteminizde bulunamadı!",
        "log_no_npcap_desc": "PPPoE paketlerini dinlemek için bilgisayarınızda Npcap kurulu olmalıdır.",
        "log_npcap_inst": "Aşağıdaki butona tıklayarak otomatik kurabilirsiniz.",
        "log_listening_start": "Seçilen ağ kartı üzerinden dinleme başlatılıyor: {desc}",
        "log_ready_wait": "Modemden PPPoE istekleri bekleniyor... Lütfen modemi kapatıp açın veya WAN kablosunu çıkarıp takın.",
        "log_err_mac": "Arayüz MAC adresi alınamadı: {err}",
        "log_err_sniff": "Dinleme hatası: {err}",
        "log_listening_stop": "Dinleme durduruldu.",
        "log_padi": "PADI (Keşif Başlatma) yakalandı! Gönderen MAC: {mac}",
        "log_pado": "PADO (Teklif) gönderildi.",
        "log_padr": "PADR (Oturum İsteği) yakalandı! Gönderen MAC: {mac}",
        "log_pads": "PADS (Oturum Onaylandı) gönderildi. Oturum ID: {session_id}",
        "log_lcp_req": "Modem LCP Yapılandırma İsteği (Configure-Request) gönderdi.",
        "log_lcp_ack": "LCP Yapılandırma Onayı (Configure-Ack) gönderildi.",
        "log_lcp_pap": "Sunucu LCP PAP İstek Paketi gönderildi.",
        "log_lcp_pap_ack": "Modem PAP isteğimizi kabul etti (LCP Configure-Ack).",
        "log_lcp_pap_nak": "Modem PAP kimlik doğrulamasını reddetti veya NAK gönderdi. PAP zorlanıyor...",
        "log_success": "🎉 BAŞARILI! PPPoE Bilgileri Yakalandı!",
        "log_user": "Kullanıcı Adı: {user}",
        "log_pass": "Şifre: {password}",
        "log_pap_err": "PAP paketi ayrıştırılırken hata oluştu: {err}",
        "log_num_ifaces": "{num} adet ağ kartı algılandı.",
        "log_no_ifaces": "HATA: Hiçbir aktif ağ kartı bulunamadı. Npcap kurulu olduğundan emin olun.",
        "log_err_ifaces": "Ağ kartları listelenirken hata: {err}",
        "log_inst_start": "Npcap yükleyicisi indiriliyor... Lütfen bekleyin.",
        "log_inst_down_pct": "İndiriliyor %{pct}",
        "log_inst_down_done": "İndirme tamamlandı. Kurulum başlatılıyor...",
        "log_inst_installing": "Kuruluyor...",
        "log_inst_done": "Kurulum tamamlandı! Sistem denetleniyor...",
        "log_inst_err": "Npcap kurulumu başarısız: {err}",
        "msg_success_title": "Başarılı!",
        "msg_success_desc": "WAN Bilgileri Yakalandı!\n\nKullanıcı Adı: {username}",
        "msg_copied_title": "Kopyalandı",
        "msg_copied_desc": "Pano üzerine kopyalandı!",
        "msg_copy_err_title": "Kopyalanamadı",
        "msg_copy_err_desc": "Kopyalanacak veri yok!",
        "msg_err_dep_title": "Bağımlılık Hatası",
        "msg_err_dep_desc": "Scapy kütüphanesi yüklenemedi. Lütfen yönetici haklarıyla çalıştırdığınızdan emin olun.",
        "msg_err_iface_title": "Hata",
        "msg_err_iface_desc": "Lütfen geçerli bir fiziksel Ethernet kartı seçin.",
        "msg_err_inst_title": "Hata",
        "msg_err_inst_desc": "Npcap indirilirken veya kurulurken hata oluştu:\n{err}"
    },
    "en": {
        "window_title": "Fiber WAN Password Extractor - Designed by HamsoTR",
        "title": "FIBER WAN CREDENTIAL EXTRACTOR",
        "subtitle": "Tool to extract WAN (PPPoE) username and password of fiber routers",
        "label_iface": "1. Select Network Interface (Ethernet Card)",
        "label_steps": "2. Connection Guide",
        "btn_refresh": "Refresh Cards",
        "btn_npcap": "Install Npcap Driver",
        "btn_start": "START LISTENING",
        "btn_stop": "STOP LISTENING",
        "label_captured": "🔑 CAPTURED CREDENTIALS",
        "label_username": "Username:",
        "label_password": "WAN Password: ",
        "btn_copy": "Copy",
        "label_log": "📋 SYSTEM LOG",
        "instructions": (
            "EXTRACTION STEPS:\n\n"
            "Step 1: Unplug the WAN cable coming from the ONT (fiber box) from your router's WAN port.\n\n"
            "Step 2: Connect your router's WAN port to this PC's Ethernet port using a standard Ethernet cable.\n\n"
            "Step 3: Select your physical Ethernet card from the dropdown above and click 'START LISTENING'.\n\n"
            "Step 4: Power off your fiber router using its power button, then power it back on (or unplug and replug its power cable).\n\n"
            "As the router boots up, it will send PPPoE requests to your PC and the password will automatically appear on the right!"
        ),
        "log_checking": "Checking system...",
        "log_ready": "Required drivers (Npcap/WinPcap) are ready.",
        "log_no_npcap": "WARNING: Npcap driver not found on your system!",
        "log_no_npcap_desc": "Npcap must be installed on your PC to listen for PPPoE packets.",
        "log_npcap_inst": "You can install it automatically by clicking the button below.",
        "log_listening_start": "Listening started on selected network card: {desc}",
        "log_ready_wait": "Waiting for PPPoE requests from router... Please power off/on the router or unplug/replug the WAN cable.",
        "log_err_mac": "Failed to get interface MAC address: {err}",
        "log_err_sniff": "Sniffing error: {err}",
        "log_listening_stop": "Listening stopped.",
        "log_padi": "PADI (Discovery Initiation) captured! Sender MAC: {mac}",
        "log_pado": "PADO (Offer) sent.",
        "log_padr": "PADR (Session Request) captured! Sender MAC: {mac}",
        "log_pads": "PADS (Session Confirmed) sent. Session ID: {session_id}",
        "log_lcp_req": "Router sent LCP Configure-Request.",
        "log_lcp_ack": "LCP Configure-Ack sent.",
        "log_lcp_pap": "Server LCP PAP Request Packet sent.",
        "log_lcp_pap_ack": "Router accepted our PAP request (LCP Configure-Ack).",
        "log_lcp_pap_nak": "Router rejected PAP auth or sent NAK. Forcing PAP...",
        "log_success": "🎉 SUCCESS! PPPoE Credentials Captured!",
        "log_user": "Username: {user}",
        "log_pass": "Password: {password}",
        "log_pap_err": "Error parsing PAP packet: {err}",
        "log_num_ifaces": "{num} network card(s) detected.",
        "log_no_ifaces": "ERROR: No active network cards found. Ensure Npcap is installed.",
        "log_err_ifaces": "Error listing network cards: {err}",
        "log_inst_start": "Downloading Npcap installer... Please wait.",
        "log_inst_down_pct": "Downloading %{pct}",
        "log_inst_down_done": "Download complete. Starting installation...",
        "log_inst_installing": "Installing...",
        "log_inst_done": "Installation complete! Rechecking system...",
        "log_inst_err": "Npcap installation failed: {err}",
        "msg_success_title": "Success!",
        "msg_success_desc": "WAN Credentials Captured!\n\nUsername: {username}",
        "msg_copied_title": "Copied",
        "msg_copied_desc": "Copied to clipboard!",
        "msg_copy_err_title": "Copy Failed",
        "msg_copy_err_desc": "No data to copy!",
        "msg_err_dep_title": "Dependency Error",
        "msg_err_dep_desc": "Scapy library could not be loaded. Please ensure you are running as administrator.",
        "msg_err_iface_title": "Error",
        "msg_err_iface_desc": "Please select a valid physical Ethernet card.",
        "msg_err_inst_title": "Error",
        "msg_err_inst_desc": "Error occurred while downloading or installing Npcap:\n{err}"
    }
}

class FiberExtractorGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.current_lang = "tr"  # Default Turkish

        self.title(self.get_text("window_title"))
        self.geometry("900x680")
        self.resizable(False, False)

        # Variables
        self.sniffer_thread = None
        self.selected_interface = tk.StringVar()
        self.interfaces = {}
        self.raw_logs = []  # Maintain log entries for translation on-the-fly

        # Set up UI grid
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.create_widgets()
        
        # Check Dependencies
        self.after(500, self.check_dependencies)

    def get_text(self, key, **kwargs):
        lang = self.current_lang
        text = TRANSLATIONS[lang].get(key, key)
        if kwargs:
            return text.format(**kwargs)
        return text

    def log(self, text, tag="info"):
        self.log_text.configure(state="normal")
        color = "#ffffff"
        if tag == "error":
            color = "#ff4d4d"
        elif tag == "warning":
            color = "#ffaa00"
        elif tag == "success":
            color = "#00ff66"
            
        self.log_text.insert("end", f"{text}\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def create_widgets(self):
        # Header Frame
        header_frame = ctk.CTkFrame(self, height=80, corner_radius=0, fg_color="#1E1E24")
        header_frame.pack(fill="x", side="top")
        
        self.title_label = ctk.CTkLabel(
            header_frame, 
            text=self.get_text("title"), 
            font=ctk.CTkFont(family="Helvetica", size=22, weight="bold"),
            text_color="#00ADB5"
        )
        self.title_label.pack(pady=(15, 2), side="left", padx=20)
        
        # Language Selector
        self.lang_var = tk.StringVar(value="Türkçe")
        self.lang_dropdown = ctk.CTkOptionMenu(
            header_frame,
            variable=self.lang_var,
            values=["Türkçe", "English"],
            command=self.change_language,
            width=100,
            fg_color="#393E46",
            button_color="#00ADB5",
            button_hover_color="#008F96"
        )
        self.lang_dropdown.pack(side="right", padx=20, pady=(20, 10))

        # Main Layout Frame
        main_frame = ctk.CTkFrame(self, fg_color="transparent")
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Left Column (Instructions & Settings)
        left_frame = ctk.CTkFrame(main_frame, width=420, fg_color="#222831", corner_radius=12)
        left_frame.pack(side="left", fill="both", expand=True, padx=(0, 10))

        # 1. Interface Selector
        self.iface_label = ctk.CTkLabel(
            left_frame, 
            text=self.get_text("label_iface"), 
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#00ADB5"
        )
        self.iface_label.pack(anchor="w", padx=20, pady=(20, 5))

        self.iface_dropdown = ctk.CTkOptionMenu(
            left_frame, 
            variable=self.selected_interface, 
            values=["Ağ kartları yükleniyor..." if self.current_lang == "tr" else "Loading network cards..."],
            width=360,
            fg_color="#393E46",
            button_color="#00ADB5",
            button_hover_color="#008F96"
        )
        self.iface_dropdown.pack(padx=20, pady=5)

        # Action buttons frame (Refresh / Npcap install)
        btn_frame = ctk.CTkFrame(left_frame, fg_color="transparent")
        btn_frame.pack(anchor="w", padx=20, pady=(5, 15), fill="x")

        self.refresh_btn = ctk.CTkButton(
            btn_frame, 
            text=self.get_text("btn_refresh"), 
            command=self.load_interfaces,
            fg_color="transparent",
            border_width=1,
            border_color="#00ADB5",
            text_color="#00ADB5",
            hover_color="#393E46",
            width=170
        )
        self.refresh_btn.pack(side="left", padx=(0, 10))

        self.npcap_btn = ctk.CTkButton(
            btn_frame, 
            text=self.get_text("btn_npcap"), 
            command=self.start_npcap_install,
            fg_color="#dc3545",
            hover_color="#c82333",
            text_color="#ffffff",
            width=180
        )
        self.npcap_btn.pack_forget() # Hidden by default

        # 2. Connection Steps Guide
        self.steps_label = ctk.CTkLabel(
            left_frame, 
            text=self.get_text("label_steps"), 
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#00ADB5"
        )
        self.steps_label.pack(anchor="w", padx=20, pady=(10, 5))

        self.steps_textbox = ctk.CTkTextbox(
            left_frame, 
            width=360, 
            height=260, 
            fg_color="#393E46", 
            text_color="#EEEEEE", 
            font=ctk.CTkFont(size=12)
        )
        self.steps_textbox.pack(padx=20, pady=5)
        self.steps_textbox.insert("1.0", self.get_text("instructions"))
        self.steps_textbox.configure(state="disabled")

        # Action Buttons
        self.action_btn = ctk.CTkButton(
            left_frame, 
            text=self.get_text("btn_start"), 
            font=ctk.CTkFont(size=16, weight="bold"),
            height=50,
            width=360,
            fg_color="#28a745",
            hover_color="#218838",
            command=self.toggle_sniffer
        )
        self.action_btn.pack(padx=20, pady=(20, 20))

        # Right Column (Logs & Result)
        right_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        right_frame.pack(side="right", fill="both", expand=True, padx=(10, 0))

        # Credentials Output Box
        cred_frame = ctk.CTkFrame(right_frame, fg_color="#222831", corner_radius=12)
        cred_frame.pack(fill="x", pady=(0, 15))

        self.cred_title = ctk.CTkLabel(
            cred_frame, 
            text=self.get_text("label_captured"), 
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#00ADB5"
        )
        self.cred_title.pack(anchor="w", padx=20, pady=(15, 10))

        # Username Display
        usr_frame = ctk.CTkFrame(cred_frame, fg_color="transparent")
        usr_frame.pack(fill="x", padx=20, pady=5)
        
        self.usr_label = ctk.CTkLabel(usr_frame, text=self.get_text("label_username"), font=ctk.CTkFont(size=12, weight="bold"))
        self.usr_label.pack(side="left")
        
        self.usr_entry = ctk.CTkEntry(usr_frame, width=220, fg_color="#393E46", state="readonly")
        self.usr_entry.pack(side="left", padx=10)
        
        self.usr_copy = ctk.CTkButton(
            usr_frame, 
            text=self.get_text("btn_copy"), 
            width=60, 
            fg_color="#00ADB5", 
            hover_color="#008F96",
            command=lambda: self.copy_to_clipboard(self.usr_entry.get())
        )
        self.usr_copy.pack(side="left")

        # Password Display
        pwd_frame = ctk.CTkFrame(cred_frame, fg_color="transparent")
        pwd_frame.pack(fill="x", padx=20, pady=(5, 20))
        
        self.pwd_label = ctk.CTkLabel(pwd_frame, text=self.get_text("label_password"), font=ctk.CTkFont(size=12, weight="bold"))
        self.pwd_label.pack(side="left")
        
        self.pwd_entry = ctk.CTkEntry(pwd_frame, width=220, fg_color="#393E46", state="readonly")
        self.pwd_entry.pack(side="left", padx=10)
        
        self.pwd_copy = ctk.CTkButton(
            pwd_frame, 
            text=self.get_text("btn_copy"), 
            width=60, 
            fg_color="#00ADB5", 
            hover_color="#008F96",
            command=lambda: self.copy_to_clipboard(self.pwd_entry.get())
        )
        self.pwd_copy.pack(side="left")

        # Real-time Console Log Box
        log_frame = ctk.CTkFrame(right_frame, fg_color="#222831", corner_radius=12)
        log_frame.pack(fill="both", expand=True)

        self.log_title = ctk.CTkLabel(
            log_frame, 
            text=self.get_text("label_log"), 
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#00ADB5"
        )
        self.log_title.pack(anchor="w", padx=20, pady=(15, 5))

        self.log_text = ctk.CTkTextbox(
            log_frame, 
            fg_color="#1E1E24", 
            text_color="#EEEEEE", 
            font=ctk.CTkFont(family="Consolas", size=11)
        )
        self.log_text.pack(fill="both", expand=True, padx=20, pady=(5, 20))
        self.log_text.configure(state="disabled")

    def change_language(self, choice):
        self.current_lang = "tr" if choice == "Türkçe" else "en"
        
        # Update Window Title
        self.title(self.get_text("window_title"))

        # Update GUI elements
        self.title_label.configure(text=self.get_text("title"))
        self.iface_label.configure(text=self.get_text("label_iface"))
        self.refresh_btn.configure(text=self.get_text("btn_refresh"))
        self.npcap_btn.configure(text=self.get_text("btn_npcap"))
        self.steps_label.configure(text=self.get_text("label_steps"))

        self.steps_textbox.configure(state="normal")
        self.steps_textbox.delete("1.0", "end")
        self.steps_textbox.insert("1.0", self.get_text("instructions"))
        self.steps_textbox.configure(state="disabled")

        if self.sniffer_thread and self.sniffer_thread.running:
            self.action_btn.configure(text=self.get_text("btn_stop"))
        else:
            self.action_btn.configure(text=self.get_text("btn_start"))

        self.cred_title.configure(text=self.get_text("label_captured"))
        self.usr_label.configure(text=self.get_text("label_username"))
        self.pwd_label.configure(text=self.get_text("label_password"))
        self.usr_copy.configure(text=self.get_text("btn_copy"))
        self.pwd_copy.configure(text=self.get_text("btn_copy"))
        self.log_title.configure(text=self.get_text("label_log"))

        # Re-render logs in selected language
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")
        
        for entry in self.raw_logs:
            if entry["type"] == "log_event":
                translated = self.get_text(entry["key"], **entry["kwargs"])
                self.log(translated, entry["level"])
            else:
                self.log(entry["message"], entry["level"])

    def check_dependencies(self):
        if not SCAPY_AVAILABLE:
            messagebox.showerror(
                self.get_text("msg_err_dep_title"), 
                self.get_text("msg_err_dep_desc")
            )
            return

        self.log_event("log_checking")
        # Check for Npcap / WinPcap
        try:
            get_working_ifaces()
            self.log_event("log_ready", "success")
            self.npcap_btn.pack_forget()  # Hide button if Npcap is present
            self.load_interfaces()
        except Exception as e:
            self.log_event("log_no_npcap", "error")
            self.log_event("log_no_npcap_desc", "warning")
            self.log_event("log_npcap_inst", "info")
            self.npcap_btn.pack(side="left")  # Show button if Npcap is missing
            self.load_interfaces()

    def start_npcap_install(self):
        self.npcap_btn.configure(state="disabled", text=self.get_text("log_inst_installing"))
        threading.Thread(target=self.download_and_install_npcap, daemon=True).start()

    def download_and_install_npcap(self):
        try:
            self.log_event("log_inst_start")
            url = "https://npcap.com/dist/npcap-1.79.exe"
            temp_dir = tempfile.gettempdir()
            installer_path = os.path.join(temp_dir, "npcap-1.79.exe")
            
            # Download file with progress updates
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req) as response:
                total_size = int(response.info().get('Content-Length', 0))
                downloaded = 0
                chunk_size = 65536
                
                with open(installer_path, 'wb') as out_file:
                    while True:
                        chunk = response.read(chunk_size)
                        if not chunk:
                            break
                        out_file.write(chunk)
                        downloaded += len(chunk)
                        if total_size > 0:
                            percent = int((downloaded / total_size) * 100)
                            self.npcap_btn.configure(text=self.get_text("log_inst_down_pct", pct=percent))
                            
            self.log_event("log_inst_down_done")
            self.npcap_btn.configure(text=self.get_text("log_inst_installing"))
            
            # Run the installer
            subprocess.run([installer_path], check=True)
            self.log_event("log_inst_done", "success")
            
            # Recheck dependencies
            self.after(500, self.check_dependencies)
        except Exception as e:
            self.log_event("log_inst_err", "error", err=str(e))
            messagebox.showerror(
                self.get_text("msg_err_inst_title"), 
                self.get_text("msg_err_inst_desc", err=str(e))
            )
        finally:
            # Re-enable button in case it failed
            self.npcap_btn.configure(text=self.get_text("btn_npcap"), state="normal")

    def load_interfaces(self):
        if not SCAPY_AVAILABLE:
            return
            
        try:
            ifaces = get_working_ifaces()
            self.interfaces = {}
            for iface in ifaces:
                desc = iface.description if iface.description else iface.name
                self.interfaces[desc] = iface.name
            
            if self.interfaces:
                menu_values = list(self.interfaces.keys())
                self.iface_dropdown.configure(values=menu_values)
                self.selected_interface.set(menu_values[0])
                self.log_event("log_num_ifaces", "success", num=len(menu_values))
            else:
                empty_msg = "Algılanan ağ kartı yok!" if self.current_lang == "tr" else "No network card detected!"
                self.iface_dropdown.configure(values=[empty_msg])
                self.selected_interface.set(empty_msg)
                self.log_event("log_no_ifaces", "error")
        except Exception as e:
            self.log_event("log_err_ifaces", "error", err=str(e))

    def toggle_sniffer(self):
        if self.sniffer_thread and self.sniffer_thread.running:
            # Stop Sniffer
            self.sniffer_thread.stop_sniffer()
            self.action_btn.configure(
                text=self.get_text("btn_start"), 
                fg_color="#28a745",
                hover_color="#218838"
            )
        else:
            # Start Sniffer
            iface_desc = self.selected_interface.get()
            if iface_desc not in self.interfaces:
                messagebox.showerror(
                    self.get_text("msg_err_iface_title"), 
                    self.get_text("msg_err_iface_desc")
                )
                return

            iface_name = self.interfaces[iface_desc]
            
            # Clear previous results
            self.usr_entry.configure(state="normal")
            self.pwd_entry.configure(state="normal")
            self.usr_entry.delete(0, "end")
            self.pwd_entry.delete(0, "end")
            self.usr_entry.configure(state="readonly")
            self.pwd_entry.configure(state="readonly")

            self.log_event("log_listening_start", desc=iface_desc)
            
            self.sniffer_thread = PPPoESniffer(interface=iface_name, callback=self.on_sniffer_update)
            self.sniffer_thread.daemon = True
            self.sniffer_thread.start()
            
            self.action_btn.configure(
                text=self.get_text("btn_stop"), 
                fg_color="#dc3545",
                hover_color="#c82333"
            )

    def log_event(self, key, level="info", **kwargs):
        # Save raw event so we can re-render it if language changes
        self.raw_logs.append({
            "type": "log_event",
            "key": key,
            "level": level,
            "kwargs": kwargs
        })
        # Log translated message
        translated = self.get_text(key, **kwargs)
        self.log(translated, level)

    def on_sniffer_update(self, data):
        if data["type"] == "log":
            self.raw_logs.append({
                "type": "log",
                "message": data["message"],
                "level": data["level"]
            })
            self.log(data["message"], data["level"])
        elif data["type"] == "log_event":
            self.log_event(data["key"], data["level"], **data["kwargs"])
        elif data["type"] == "credentials":
            self.usr_entry.configure(state="normal")
            self.pwd_entry.configure(state="normal")
            self.usr_entry.insert(0, data["username"])
            self.pwd_entry.insert(0, data["password"])
            self.usr_entry.configure(state="readonly")
            self.pwd_entry.configure(state="readonly")
            
            self.action_btn.configure(
                text=self.get_text("btn_start"), 
                fg_color="#28a745",
                hover_color="#218838"
            )
            
            messagebox.showinfo(
                self.get_text("msg_success_title"), 
                self.get_text("msg_success_desc", username=data["username"])
            )

    def copy_to_clipboard(self, text):
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            self.update()
            messagebox.showinfo(
                self.get_text("msg_copied_title"), 
                self.get_text("msg_copied_desc")
            )
        else:
            messagebox.showwarning(
                self.get_text("msg_copy_err_title"), 
                self.get_text("msg_copy_err_desc")
            )

if __name__ == "__main__":
    # Elevated privilege check
    # Under Windows, raw sockets require Administrator privileges
    if os.name == 'nt':
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            # Try to run as admin
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            sys.exit(0)

    app = FiberExtractorGUI()
    app.mainloop()
