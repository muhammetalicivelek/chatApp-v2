from PIL import Image

# Verinin bittiğini anlamamızı sağlayan işaret
STOP_INDICATOR = "#####"

def str_to_bin(message):
    """Yazıyı 0 ve 1'lere çevirir."""
    binary_str = ""
    byte_array = message.encode('utf-8')
    for byte in byte_array:
        binary_str += format(byte, '08b')
    return binary_str

def bin_to_str(binary_data):
    """0 ve 1'leri yazıya çevirir."""
    message = ""
    for i in range(0, len(binary_data), 8):
        byte = binary_data[i:i+8]
        message += chr(int(byte, 2))
    return message

def embed_data(image_path, secret_data, output_path):
    """Resmin içine veri gizler."""
    image = Image.open(image_path)
    image = image.convert("RGB")
    
    full_data = secret_data + STOP_INDICATOR
    binary_data = str_to_bin(full_data)
    data_len = len(binary_data)
    
    pixels = image.load()
    width, height = image.size
    
    data_index = 0
    
    for y in range(height):
        for x in range(width):
            if data_index >= data_len:
                break
            
            r, g, b = pixels[x, y]
            
            # Kırmızı
            if data_index < data_len:
                r = (r & 254) | int(binary_data[data_index])
                data_index += 1
            
            # Yeşil
            if data_index < data_len:
                g = (g & 254) | int(binary_data[data_index])
                data_index += 1
                
            # Mavi
            if data_index < data_len:
                b = (b & 254) | int(binary_data[data_index])
                data_index += 1
            
            pixels[x, y] = (r, g, b)
        
        if data_index >= data_len:
            break

    image.save(output_path, "PNG")
    return output_path

def extract_data(image_path):
    """Resimden gizli veriyi okur."""
    image = Image.open(image_path)
    image = image.convert("RGB")
    pixels = image.load()
    
    binary_data = ""
    width, height = image.size
    
    # Tüm pikselleri tara (Basit yöntem)
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            binary_data += str(r & 1)
            binary_data += str(g & 1)
            binary_data += str(b & 1)
            
    # Byte'lara çevir ve durdurucuyu ara
    all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    
    decoded_msg = ""
    for byte in all_bytes:
        try:
            char = chr(int(byte, 2))
            decoded_msg += char
            if decoded_msg.endswith(STOP_INDICATOR):
                return decoded_msg[:-len(STOP_INDICATOR)]
        except:
            continue
            
    return "Veri Bulunamadı"
