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
    print(f"[+] Yeni Bağlantı: {address}")
    current_user = None

    while True:
        try:
            data = protocol.recv_packet(client_socket)
            if not data: break

            req = protocol.parse_msg(data)
            msg_type = req.get("type")

            # 1. KAYIT
            if msg_type == protocol.MSG_REGISTER:
                username = req.get("username")
                img_hex = req.get("image_data")
                
                # Geçici dosya işlemleri
                os.makedirs("server/data", exist_ok=True)
                tmp_path = f"server/data/temp_{username}.png"
                with open(tmp_path, "wb") as f: f.write(bytes.fromhex(img_hex))
                
                extracted_pass = steganography.extract_data(tmp_path)
                if os.path.exists(tmp_path): os.remove(tmp_path)

                if "Veri Bulunamadı" in extracted_pass:
                    protocol.send_packet(client_socket, protocol.create_msg(protocol.MSG_ERROR, message="Resimde şifre yok!"))
                else:
                    if db_manager.add_user(username, extracted_pass):
                        print(f"✅ Kayıt: {username}")
                        protocol.send_packet(client_socket, protocol.create_msg("REGISTER_OK"))
                        broadcast_user_list()
                    else:
                        protocol.send_packet(client_socket, protocol.create_msg(protocol.MSG_ERROR, message="Kullanıcı adı dolu."))

            # 2. GİRİŞ
            elif msg_type == protocol.MSG_LOGIN:
                user = req.get("username")
                pwd = req.get("password")
                saved_pass = db_manager.get_user_password(user)
                
                if saved_pass and saved_pass == pwd:
                    current_user = user
                    active_clients[user] = client_socket
                    print(f"✅ Online: {user} ({address[0]})")
                    
                    # Bekleyen mesajları ilet
                    for msg in db_manager.get_offline_messages(user):
                        pkt = protocol.create_msg(protocol.MSG_INCOMING, sender=msg['sender'], message=msg['message'])
                        protocol.send_packet(client_socket, pkt)
                    
                    broadcast_user_list()
                else:
                    protocol.send_packet(client_socket, protocol.create_msg(protocol.MSG_ERROR, message="Hatalı giriş."))

            # 3. MESAJLAŞMA (Routing)
            elif msg_type == protocol.MSG_SEND:
                target = req.get("to")
                encrypted_msg = req.get("message")
                
                # Şifre çözme/tekrar şifreleme mantığı (Server-Side Decryption)
                sender_pass = db_manager.get_user_password(current_user)
                plain = security.decrypt_des(encrypted_msg, sender_pass)
                
                if plain:
                    target_pass = db_manager.get_user_password(target)
                    if target_pass:
                        re_encrypted = security.encrypt_des(plain, target_pass)
                        
                        if target in active_clients:
                            pkt = protocol.create_msg(protocol.MSG_INCOMING, sender=current_user, message=re_encrypted)
                            protocol.send_packet(active_clients[target], pkt)
                        else:
                            db_manager.add_offline_message(target, current_user, re_encrypted)
                
            elif msg_type == protocol.MSG_LOGOUT:
                break

        except Exception as e:
            print(f"Hata ({address}): {e}")
            break

    # Temizlik
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