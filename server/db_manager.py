import json
import os

# Dosya yollarını tanımlayalım
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')

USERS_FILE = os.path.join(DATA_DIR, 'users.json')
MESSAGES_FILE = os.path.join(DATA_DIR, 'messages.json')

# Eğer data klasörü yoksa oluştur (Garanti olsun)
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

# --- YARDIMCI FONKSİYONLAR ---
def _load_json(filepath):
    """Verilen dosyayı okur ve Python sözlüğü (dict) olarak döndürür."""
    if not os.path.exists(filepath):
        return {}
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except:
        return {}

def _save_json(filepath, data):
    """Verilen veriyi (dict) dosyaya kaydeder."""
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4) # indent=4 okunabilir olsun diye

# --- KULLANICI YÖNETİMİ ---
def add_user(username, password):
    """Yeni kullanıcıyı ve parolasını kaydeder."""
    users = _load_json(USERS_FILE)
    if username in users:
        return False # Kullanıcı zaten var
    
    users[username] = password
    _save_json(USERS_FILE, users)
    return True

def get_user_password(username):
    """Kullanıcının parolasını döndürür. Yoksa None döner."""
    users = _load_json(USERS_FILE)
    return users.get(username)

def get_all_users():
    """Tüm kayıtlı kullanıcıların listesini döndürür."""
    users = _load_json(USERS_FILE)
    return list(users.keys())

# --- OFFLINE MESAJ YÖNETİMİ ---
def add_offline_message(recipient, sender, encrypted_msg):
    """Bir kullanıcıya (recipient) giden mesajı kutusuna atar."""
    messages = _load_json(MESSAGES_FILE)
    
    if recipient not in messages:
        messages[recipient] = []
        
    # Mesajı listeye ekle
    msg_packet = {"sender": sender, "message": encrypted_msg}
    messages[recipient].append(msg_packet)
    
    _save_json(MESSAGES_FILE, messages)

def get_offline_messages(recipient):
    """Kullanıcının kutusundaki mesajları getirir ve kutuyu BOŞALTIR."""
    messages = _load_json(MESSAGES_FILE)
    
    if recipient in messages:
        user_msgs = messages[recipient]
        # Mesajları aldık, artık kutudan silebiliriz
        del messages[recipient]
        _save_json(MESSAGES_FILE, messages)
        return user_msgs
    else:
        return []

# --- TEST BLOĞU ---
if __name__ == "__main__":
    print("--- VERİTABANI TESTİ ---")
    
    # 1. Kullanıcı Ekleme
    if add_user("test_kullanici", "12345"):
        print("✅ Kullanıcı eklendi.")
    else:
        print("ℹ️ Kullanıcı zaten var.")
        
    # 2. Şifre Kontrol
    pwd = get_user_password("test_kullanici")
    print(f"User şifresi: {pwd}")
    
    # 3. Mesaj Bırakma
    add_offline_message("test_kullanici", "gonderen_kisi", "SifreliMesajOrnegi")
    print("✅ Offline mesaj bırakıldı.")
    
    # 4. Mesajları Çekme
    msgs = get_offline_messages("test_kullanici")
    print(f"📬 Çekilen Mesajlar: {msgs}")
    
    # 5. Tekrar Çekme (Boş olmalı)
    msgs2 = get_offline_messages("test_kullanici")
    print(f"📭 Tekrar bakıldığında (Boş olmalı): {msgs2}")