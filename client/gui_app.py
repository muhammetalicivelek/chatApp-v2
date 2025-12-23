import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog, scrolledtext
import os
import sys
import json

# Common ve Network modüllerini ekle
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import steganography
from network import NetworkManager

class ChatClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Güvenli Mesajlaşma (Ağ Tabanlı)")
        self.root.geometry("600x550") 
        
        self.network = NetworkManager(self.handle_network_event)
        
        self.target_user = None
        self.selected_image_path = None
        self.chat_histories = {}
        
        self.setup_welcome_ui()

    # --- GEÇMİŞ YÖNETİMİ ---
    def _get_history_filename(self):
        if self.network.username:
            return f"client/data/history_{self.network.username}.json"
        return "client/data/history_unknown.json"

    def _load_history_from_disk(self):
        filename = self._get_history_filename()
        if os.path.exists(filename):
            try:
                with open(filename, "r", encoding="utf-8") as f:
                    self.chat_histories = json.load(f)
            except Exception as e:
                print(f"Geçmiş yükleme hatası: {e}")
                self.chat_histories = {}
        else:
            self.chat_histories = {}

    def _save_history_to_disk(self):
        if not self.network.username: return
        filename = self._get_history_filename()
        try:
            os.makedirs("client/data", exist_ok=True)
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(self.chat_histories, f, ensure_ascii=False, indent=4)
        except Exception as e:
            print(f"Geçmiş kaydedilemedi: {e}")

    # --- CALLBACK ---
    def handle_network_event(self, event_type, data):
        try:
            self.root.after(0, lambda: self._process_event(event_type, data))
        except:
            pass

    def _process_event(self, event_type, data):
        if event_type == "USER_LIST":
            self.update_user_list(data.get("users"))
            
        elif event_type == "NEW_MESSAGE":
            sender = data["sender"]
            text = data["text"]
            self.receive_chat_message(sender, text)
            
        elif event_type == "ERROR":
            messagebox.showerror("Hata", data.get("message"))
            # Hata alınca giriş ekranına atabiliriz ama bağlantıyı korumak daha iyi olabilir
            # self.setup_login_ui()
            
        elif event_type == "REGISTER_OK":
            messagebox.showinfo("Başarılı", "Kayıt Başarılı! Giriş ekranına yönlendiriliyorsunuz.")
            registered_user = self.entry_reg_user.get()
            self.network.disconnect()
            self.setup_login_ui(prefill_user=registered_user)
            
        elif event_type == "DISCONNECTED":
            # Bağlantı koptuğunda uyarı ver
             pass

    # --- EKRAN YÖNETİMİ ---
    def clear_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def setup_welcome_ui(self):
        self.clear_ui()
        tk.Label(self.root, text="Güvenli Sohbet v3", font=("Arial", 16)).pack(pady=20)
        tk.Button(self.root, text="Giriş Yap", width=20, command=self.setup_login_ui).pack(pady=10)
        tk.Button(self.root, text="Kayıt Ol", width=20, command=self.setup_register_ui).pack(pady=10)

    def setup_login_ui(self, prefill_user=None):
        self.clear_ui()
        self.chat_histories = {} 
        
        tk.Label(self.root, text="Giriş Yap", font=("Arial", 14)).pack(pady=10)
        
        # -- IP Kutusu --
        tk.Label(self.root, text="Sunucu IP Adresi:").pack()
        self.entry_ip = tk.Entry(self.root)
        self.entry_ip.insert(0, "192.168.1.XX") # Varsayılan örnek
        self.entry_ip.pack()
        
        tk.Label(self.root, text="Kullanıcı Adı:").pack()
        self.entry_user = tk.Entry(self.root)
        self.entry_user.pack()
        if prefill_user: self.entry_user.insert(0, prefill_user)
        
        self.btn_login = tk.Button(self.root, text="Bağlan ve Giriş", command=self.perform_login)
        self.btn_login.pack(pady=10)
        tk.Button(self.root, text="Geri", command=self.setup_welcome_ui).pack()

    def setup_register_ui(self):
        self.clear_ui()
        tk.Label(self.root, text="Kayıt Ol", font=("Arial", 14)).pack(pady=10)
        
        # -- IP Kutusu (Kayıt olurken de bağlanmak lazım) --
        tk.Label(self.root, text="Sunucu IP Adresi:").pack()
        self.entry_reg_ip = tk.Entry(self.root)
        self.entry_reg_ip.insert(0, "192.168.1.XX")
        self.entry_reg_ip.pack()
        
        tk.Label(self.root, text="Kullanıcı Adı:").pack()
        self.entry_reg_user = tk.Entry(self.root)
        self.entry_reg_user.pack()
        
        tk.Label(self.root, text="Parola (Resme gizlenecek):").pack()
        self.entry_reg_pass = tk.Entry(self.root, show="*")
        self.entry_reg_pass.pack()
        
        self.lbl_file = tk.Label(self.root, text="Resim seçilmedi", fg="red")
        self.lbl_file.pack(pady=5)
        
        tk.Button(self.root, text="Resim Seç", command=self.choose_file).pack()
        tk.Button(self.root, text="Kaydol", bg="green", fg="white", command=self.perform_register).pack(pady=20)
        tk.Button(self.root, text="Geri", command=self.setup_welcome_ui).pack()

    def setup_chat_ui(self, username):
        self.clear_ui()
        self.root.title(f"Sohbet: {username} | Sunucu: {self.network.host}")
        
        body = tk.Frame(self.root)
        body.pack(fill=tk.BOTH, expand=True)
        
        # SOL (Liste)
        left = tk.Frame(body, width=200, bg="#e0e0e0")
        left.pack(side=tk.LEFT, fill=tk.Y)
        left.pack_propagate(False) 
        
        tk.Label(left, text="KİŞİLER", bg="#ccc", font=("Arial", 10, "bold")).pack(fill=tk.X, ipady=5)
        self.user_listbox = tk.Listbox(left, font=("Arial", 11), selectbackground="#4a90e2")
        self.user_listbox.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        self.user_listbox.bind('<<ListboxSelect>>', self.on_user_select)

        btn_logout = tk.Button(left, text="Çıkış Yap", bg="#c0392b", fg="white", 
                               command=self.perform_logout)
        btn_logout.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)
        
        # SAĞ (Mesaj)
        right = tk.Frame(body, bg="white")
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        header_frm = tk.Frame(right, bg="white")
        header_frm.pack(fill=tk.X, pady=5, padx=5)

        self.lbl_target = tk.Label(header_frm, text="Sohbet Başlatmak İçin Bir Kişi Seçin", 
                                 bg="white", fg="gray", font=("Arial", 12))
        self.lbl_target.pack(side=tk.LEFT, padx=10)

        self.btn_clear_history = tk.Button(header_frm, text="Geçmişi Temizle", bg="#f39c12", fg="white",
                                           font=("Arial", 9), state="disabled", 
                                           command=self.clear_current_history)
        self.btn_clear_history.pack(side=tk.RIGHT, padx=10)
        
        self.chat_area = scrolledtext.ScrolledText(right, state='disabled', height=20, font=("Consolas", 10))
        self.chat_area.pack(fill=tk.BOTH, expand=True, padx=10)
        
        input_frm = tk.Frame(right, bg="#f0f0f0", height=50)
        input_frm.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.msg_entry = tk.Entry(input_frm, font=("Arial", 11))
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10, pady=10)
        self.msg_entry.bind("<Return>", lambda e: self.send_message())
        
        send_btn = tk.Button(input_frm, text="Gönder", bg="#4a90e2", fg="white", 
                           font=("Arial", 10, "bold"), command=self.send_message)
        send_btn.pack(side=tk.RIGHT, padx=10, pady=10)

    # --- AKSİYONLAR ---
    def perform_logout(self):
        if messagebox.askyesno("Çıkış", "Oturumu kapatmak istediğinize emin misiniz?"):
            self.network.send_logout() 
            self.network.disconnect()
            self.setup_login_ui()

    def clear_current_history(self):
        if not self.target_user: return
        if messagebox.askyesno("Geçmişi Sil", f"{self.target_user} ile olan tüm mesajlaşma geçmişi silinsin mi?"):
            if self.target_user in self.chat_histories:
                del self.chat_histories[self.target_user]
            
            self.chat_area.config(state='normal')
            self.chat_area.delete(1.0, tk.END)
            self.chat_area.config(state='disabled')
            self._save_history_to_disk()
            messagebox.showinfo("Başarılı", "Geçmiş temizlendi.")    

    def choose_file(self):
        f = filedialog.askopenfilename(filetypes=[("Images", "*.png *.jpg")])
        if f:
            self.selected_image_path = f
            self.lbl_file.config(text=os.path.basename(f), fg="blue")

    def perform_register(self):
        ip = self.entry_reg_ip.get()
        user = self.entry_reg_user.get()
        pwd = self.entry_reg_pass.get()
        
        if not user or not pwd or not self.selected_image_path:
            messagebox.showwarning("Eksik", "Bilgileri doldurun!")
            return
        
        # 1. Önce bağlan
        success, msg = self.network.connect(ip)
        if success:
            try:
                os.makedirs("client/assets", exist_ok=True)
                output_path = f"client/assets/steg_{user}.png"
                steganography.embed_data(self.selected_image_path, pwd, output_path)
                with open(output_path, "rb") as f: hex_data = f.read().hex()
                self.network.send_register(user, hex_data)
            except Exception as e:
                messagebox.showerror("Hata", str(e))
        else:
            messagebox.showerror("Hata", f"Sunucuya bağlanılamadı:\n{msg}")

    def perform_login(self):
        ip = self.entry_ip.get()
        user = self.entry_user.get()
        if not user: return
        
        self.btn_login.config(state="disabled", text="Bağlanıyor...")
        self.root.update()
        
        # 1. Önce bağlan
        success, msg = self.network.connect(ip)
        if success:
            pwd = simpledialog.askstring("Şifre", "Mesajları çözmek için parolanızı:", show='*')
            if pwd:
                self.network.set_credentials(user, pwd)
                self._load_history_from_disk()
                self.setup_chat_ui(user)
                self.network.send_login(user)
            else:
                self.network.disconnect()
                self.setup_login_ui()
        else:
            messagebox.showerror("Hata", f"Sunucuya bağlanılamadı:\n{msg}")
            self.setup_login_ui()

    def on_user_select(self, event):
        sel = self.user_listbox.curselection()
        if sel:
            val = self.user_listbox.get(sel[0])
            user = val.split(" ")[0] 
            
            if user != self.network.username:
                self.target_user = user
                self.lbl_target.config(text=f"{user} ile sohbet ediliyor", fg="black")
                
                if hasattr(self, 'btn_clear_history'):
                    self.btn_clear_history.config(state="normal")
                
                self.chat_area.config(state='normal')
                self.chat_area.delete(1.0, tk.END)
                
                history = self.chat_histories.get(user, "")
                self.chat_area.insert(tk.END, history)
                self.chat_area.see(tk.END)
                self.chat_area.config(state='disabled')

    def receive_chat_message(self, sender, text):
        formatted_msg = f"[{sender}]: {text}\n"
        
        if sender not in self.chat_histories:
            self.chat_histories[sender] = ""
        self.chat_histories[sender] += formatted_msg
        
        if self.target_user == sender:
            self.chat_area.config(state='normal')
            self.chat_area.insert(tk.END, formatted_msg)
            self.chat_area.see(tk.END)
            self.chat_area.config(state='disabled')
            
        self._save_history_to_disk()

    def send_message(self):
        if not self.target_user:
            messagebox.showinfo("Bilgi", "Lütfen soldan bir kişi seçin.")
            return
        msg = self.msg_entry.get()
        if not msg: return
        
        success, info = self.network.send_chat_message(self.target_user, msg)
        
        if success:
            formatted_msg = f"[Ben]: {msg}\n"
            
            if self.target_user not in self.chat_histories:
                self.chat_histories[self.target_user] = ""
            self.chat_histories[self.target_user] += formatted_msg
            
            self.chat_area.config(state='normal')
            self.chat_area.insert(tk.END, formatted_msg)
            self.chat_area.see(tk.END)
            self.chat_area.config(state='disabled')
            
            self.msg_entry.delete(0, tk.END)
            self._save_history_to_disk()
        else:
            self.chat_area.config(state='normal')
            self.chat_area.insert(tk.END, f"[Sistem]: Hata - {info}\n")
            self.chat_area.config(state='disabled')

    def update_user_list(self, users):
        if hasattr(self, 'user_listbox'):
            current_selection = self.user_listbox.curselection()
            selected_name = None
            if current_selection:
                selected_name = self.user_listbox.get(current_selection[0])
            
            self.user_listbox.delete(0, tk.END)
            
            idx = 0
            for u in users:
                raw_name = u.split(" ")[0]
                if raw_name == self.network.username:
                    self.user_listbox.insert(tk.END, f"{u} (Sen)")
                else:
                    self.user_listbox.insert(tk.END, u)
                    if selected_name and u == selected_name:
                        self.user_listbox.selection_set(idx)
                idx += 1