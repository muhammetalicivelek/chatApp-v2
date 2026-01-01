import socket
import threading
import sys
import os

# Common klasörünü görmesi için yol ayarı
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import protocol, security, steganography
import db_manager # db_manager.py dosyasını yanına koymayı unutma

# --- KRİTİK AYAR ---
HOST = '0.0.0.0'  # Tüm ağ arayüzlerini dinle (Sadece Localhost değil!)
PORT = 5000       # Güvenlik duvarından bu porta izin vermelisin
# -------------------

active_clients = {} # {username: socket}

def handle_client(client_socket, address):
    print(f"\n[BAĞLANTI] Yeni Client Bağlandı: {address}") # Madde 1: Çoklu Client Desteği
    current_user = None

    while True:
        try:
            data = protocol.recv_packet(client_socket)
            if not data: break

            req = protocol.parse_msg(data)
            msg_type = req.get("type")

            # --- KAYIT İŞLEMİ (Madde 2, 3, 4) ---
            if msg_type == protocol.MSG_REGISTER:
                username = req.get("username")
                img_hex = req.get("image_data")
                print(f"\n[KAYIT] İstek: {username}")
                print(f" ↳ [Madde 4] Görsel verisi alındı, geçici dosyaya yazılıyor...")
                
                os.makedirs("server/data", exist_ok=True)
                tmp_path = f"server/data/temp_{username}.png"
                with open(tmp_path, "wb") as f: f.write(bytes.fromhex(img_hex))
                
                print(f" ↳ [Madde 4] Steganografi ile görsel taranıyor (LSB Analizi)...")
                extracted_pass = steganography.extract_data(tmp_path)
                
                if os.path.exists(tmp_path): os.remove(tmp_path)

                if "Veri Bulunamadı" in extracted_pass:
                    print(" ❌ HATA: Görselde gizli şifre bulunamadı!")
                    protocol.send_packet(client_socket, protocol.create_msg(protocol.MSG_ERROR, message="Resimde şifre yok!"))
                else:
                    print(f" ✅ [Madde 4] Şifre Başarıyla Çıkarıldı: {extracted_pass}")
                    if db_manager.add_user(username, extracted_pass):
                        print(f" ✅ Kullanıcı Veritabanına Eklendi.")
                        protocol.send_packet(client_socket, protocol.create_msg("REGISTER_OK"))
                        broadcast_user_list()
                    else:
                        print(f" ❌ Kullanıcı adı zaten var.")
                        protocol.send_packet(client_socket, protocol.create_msg(protocol.MSG_ERROR, message="Kullanıcı adı dolu."))

            # --- GİRİŞ İŞLEMİ (Madde 7) ---
            elif msg_type == protocol.MSG_LOGIN:
                user = req.get("username")
                pwd = req.get("password") # Client bunu şifreli yollamıyor, SSL yoksa riskli ama proje kuralı böyle
                print(f"\n[GİRİŞ] Deneme: {user}")
                
                saved_pass = db_manager.get_user_password(user)
                
                if saved_pass and saved_pass == pwd:
                    current_user = user
                    active_clients[user] = client_socket
                    print(f" ✅ Giriş Başarılı: {user}")
                    
                    # Madde 7: Offline Mesajları İletme
                    offline_msgs = db_manager.get_offline_messages(user)
                    if offline_msgs:
                        print(f" ↳ [Madde 7] {len(offline_msgs)} adet OFFLINE mesaj bulundu, iletiliyor...")
                        for msg in offline_msgs:
                            pkt = protocol.create_msg(protocol.MSG_INCOMING, sender=msg['sender'], message=msg['message'])
                            protocol.send_packet(client_socket, pkt)
                    else:
                        print(f" ↳ Offline mesaj yok.")
                    
                    broadcast_user_list()
                else:
                    print(f" ❌ Hatalı şifre veya kullanıcı.")
                    protocol.send_packet(client_socket, protocol.create_msg(protocol.MSG_ERROR, message="Hatalı giriş."))

            # --- MESAJLAŞMA VE ROUTING (Madde 6, 10, 11) ---
            elif msg_type == protocol.MSG_SEND:
                target = req.get("to")
                encrypted_msg = req.get("message")
                
                print(f"\n[MESAJ] {current_user} -> {target}")
                print(f" ↳ Şifreli Gelen Veri (Hex): {encrypted_msg[:15]}...")

                # 1. Gönderenin şifresiyle çöz (Madde 10)
                sender_pass = db_manager.get_user_password(current_user)
                plain = security.decrypt_des(encrypted_msg, sender_pass)
                
                if plain:
                    print(f" ✅ [Madde 10] Gönderen ({current_user}) anahtarıyla mesaj çözüldü: '{plain}'")
                    
                    target_pass = db_manager.get_user_password(target)
                    if target_pass:
                        # 2. Alıcının şifresiyle tekrar şifrele (Madde 11)
                        re_encrypted = security.encrypt_des(plain, target_pass)
                        print(f" 🔒 [Madde 11] Alıcı ({target}) anahtarıyla tekrar şifrelendi (Re-Encryption).")
                        
                        if target in active_clients:
                            pkt = protocol.create_msg(protocol.MSG_INCOMING, sender=current_user, message=re_encrypted)
                            protocol.send_packet(active_clients[target], pkt)
                            print(f" 📤 Hedef ONLINE. Mesaj iletildi.")
                        else:
                            # Madde 6: Offline mesaj saklama
                            db_manager.add_offline_message(target, current_user, re_encrypted)
                            print(f" 💾 [Madde 6] Hedef OFFLINE. Mesaj veritabanına kaydedildi.")
                else:
                    print(f" ❌ Şifre çözülemedi! Anahtar uyuşmazlığı.")
                
            elif msg_type == protocol.MSG_LOGOUT:
                print(f"\n[ÇIKIŞ] {current_user} çıkış yaptı.")
                break

        except Exception as e:
            print(f"Hata ({address}): {e}")
            break

    if current_user in active_clients:
        del active_clients[current_user]
        broadcast_user_list()
    client_socket.close()

def broadcast_user_list():
    users = db_manager.get_all_users()
    online_list = [u if u in active_clients else f"{u} (Offline)" for u in users]
    msg = protocol.create_msg(protocol.MSG_LIST, users=online_list)
    
    for sock in active_clients.values():
        try: protocol.send_packet(sock, msg)
        except: pass

if __name__ == "__main__":
    if not os.path.exists("server/data"): os.makedirs("server/data")
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"🚀 Sunucu Aktif! IP Adresinizden (örn: 192.168.1.XX) bağlanılabilir.")
    
    while True:
        client, addr = server.accept()
        threading.Thread(target=handle_client, args=(client, addr)).start()