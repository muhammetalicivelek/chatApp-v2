from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import binascii

# DES algoritması tam olarak 8 byte (64 bit) anahtar ister.
# Eğer kullanıcı "123" girerse bunu "12300000" gibi 8'e tamamlamalıyız.

def adjust_key_length(key_text):
    """
    Girilen parolayı DES için tam 8 byte uzunluğuna getirir.
    Kısaysa sonuna boşluk ekler, uzunsa keser.
    """
    key_bytes = key_text.encode('utf-8')
    
    if len(key_bytes) < 8:
        # 8 byte olana kadar sonuna boşluk karakteri ekle
        padded_key = key_bytes + b' ' * (8 - len(key_bytes))
        return padded_key
    else:
        # 8 byte'tan uzunsa ilk 8 karakteri al
        return key_bytes[:8]

def encrypt_des(plain_text, key):
    """
    Metni (plain_text) verilen anahtarla (key) DES kullanarak şifreler.
    Sonucu HEX string olarak döndürür.
    """
    try:
        # 1. Anahtarı 8 byte'a ayarla
        des_key = adjust_key_length(key)
        
        # 2. Şifreleme motorunu oluştur (ECB modu en basitidir)
        cipher = DES.new(des_key, DES.MODE_ECB)
        
        # 3. Metni byte'a çevir ve 8'in katı olacak şekilde doldur (Padding)
        # DES sadece 8, 16, 24... byte'lık verileri şifreleyebilir.
        data_bytes = plain_text.encode('utf-8')
        padded_data = pad(data_bytes, DES.block_size) # block_size = 8
        
        # 4. Şifrele
        encrypted_bytes = cipher.encrypt(padded_data)
        
        # 5. Sonucu okunabilir HEX formatına çevir (Örn: b'\xa3' -> 'a3')
        return encrypted_bytes.hex()
        
    except Exception as e:
        print(f"Şifreleme Hatası: {e}")
        return None

def decrypt_des(hex_data, key):
    """
    Şifreli HEX verisini (hex_data) anahtarla çözer ve orijinal metni verir.
    """
    try:
        # 1. Anahtarı 8 byte'a ayarla
        des_key = adjust_key_length(key)
        
        # 2. Şifreleme motorunu oluştur
        cipher = DES.new(des_key, DES.MODE_ECB)
        
        # 3. HEX string'i tekrar byte haline getir
        encrypted_bytes = bytes.fromhex(hex_data)
        
        # 4. Şifreyi çöz
        decrypted_padded_data = cipher.decrypt(encrypted_bytes)
        
        # 5. Dolguyu (Padding) temizle
        original_data = unpad(decrypted_padded_data, DES.block_size)
        
        return original_data.decode('utf-8')
        
    except Exception as e:
        print(f"Deşifre Hatası: {e} (Anahtar yanlış olabilir)")
        return None
