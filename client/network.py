import socket
import threading
import sys
import os

# Common klasörünü görebilmek için yol ayarı
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import protocol, security

class NetworkManager:
    def __init__(self, on_message_received_callback):
        self.socket = None
        self.host = ''       # Dinamik olarak atanacak
        self.port = 5000     # Sunucu portuyla aynı olmalı
        self.is_running = False
        self.username = None
        self.password = None # DES anahtarı olarak kullanılacak
        self.callback = on_message_received_callback

    def connect(self, ip_address):
        """Dışarıdan girilen IP adresine bağlanır"""
        self.host = ip_address
        try:
            # Varsa eski bağlantıyı kapat
            self.disconnect()
            
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(3) # 3 saniye içinde sunucuyu bulamazsa hata verir
            self.socket.connect((self.host, self.port))
            self.socket.settimeout(None) # Bağlandıktan sonra timeout kaldırılır
            
            self.is_running = True
            
            # Dinlemeyi arka planda başlat
            threading.Thread(target=self._listen_loop, daemon=True).start()
            return True, "Bağlandı"
        except Exception as e:
            print(f"Bağlantı Hatası: {e}")
            return False, str(e)

    def disconnect(self):
        """Bağlantıyı güvenli bir şekilde kapatır"""
        self.is_running = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        self.socket = None

    def set_credentials(self, username, password):
        self.username = username
        self.password = password

    def send_register(self, username, image_hex):
        if not self.socket: return
        try:
            req = protocol.create_msg(protocol.MSG_REGISTER, username=username, image_data=image_hex)
            protocol.send_packet(self.socket, req)
        except:
            self.callback("ERROR", {"message": "Sunucuya veri gönderilemedi."})

    def send_login(self, username):
        if not self.socket: return
        try:
            # Login isteği şifreyle birlikte gönderiliyor
            req = protocol.create_msg(protocol.MSG_LOGIN, 
                                    username=username, 
                                    password=self.password) 
            protocol.send_packet(self.socket, req)
        except:
            self.callback("ERROR", {"message": "Sunucuya giriş isteği gönderilemedi."})

    def send_logout(self):
        if not self.socket: return
        try:
            req = protocol.create_msg(protocol.MSG_LOGOUT)
            protocol.send_packet(self.socket, req)
        except:
            pass       

    def send_chat_message(self, target_user, plain_message):
        if not self.password:
            return False, "Şifre (Anahtar) girilmemiş!"
        
        print(f"\n---  MESAJ GÖNDERME İŞLEMİ ---")
        print(f"1. Ham Mesaj: {plain_message}")
        print(f"2. Kullanılan DES Anahtarı: {self.password}")

        try:
            # Madde 8: Mesajı DES ile şifrele
            encrypted_hex = security.encrypt_des(plain_message, self.password)
            if not encrypted_hex:
                return False, "Şifreleme başarısız oldu."
            
            print(f"3. DES Şifreli Hali (Hex): {encrypted_hex}")

            # Madde 9: Server'a ilet
            req = protocol.create_msg(protocol.MSG_SEND, to=target_user, message=encrypted_hex)
            protocol.send_packet(self.socket, req)
            print(f"4. Sunucuya paket gönderildi.")
            print(f"---------------------------------------")
            return True, "Gönderildi"
        except Exception as e:
            return False, f"Gönderme hatası: {e}"

    def _listen_loop(self):
        """Sürekli sunucuyu dinler"""
        while self.is_running:
            try:
                if not self.socket: break
                
                data = protocol.recv_packet(self.socket)
                if not data: break
                
                request = protocol.parse_msg(data)
                msg_type = request.get("type")

                if msg_type == protocol.MSG_INCOMING:
                    sender = request.get("sender")
                    encrypted_msg = request.get("message")
                    
                    print(f"\n--- GELEN MESAJ ---")
                    print(f"1. Gönderen: {sender}")
                    print(f"2. Gelen Şifreli Veri: {encrypted_msg}")
                    
                    # Gelen şifreli mesajı çöz
                    decrypted_text = security.decrypt_des(encrypted_msg, self.password)
                    if not decrypted_text:
                        decrypted_text = "[Şifre Çözülemedi - Anahtar Yanlış]"
                        print(f"3. ❌ Şifre çözülemedi!")
                    else:
                        print(f"3. DES ile Çözüldü: {decrypted_text}")

                    self.callback("NEW_MESSAGE", {"sender": sender, "text": decrypted_text})
                else:
                    self.callback(msg_type, request)

            except OSError:
                break
            except Exception as e:
                print(f"Dinleme Hatası: {e}")
                break
        
        # Döngü bittiyse bağlantı kopmuş demektir
        if self.is_running:
            self.is_running = False
            self.callback("DISCONNECTED", {"message": "Sunucu bağlantısı koptu."})