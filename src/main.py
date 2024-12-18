from cripto import generate_key, encrypt_data, decrypt_data, hash_data
from analisederede import sniff_packets
import threading
import time

def main():
    # Gerando uma chave para criptografia
    key = generate_key()
    print("Chave de criptografia gerada:", key.hex())

    # Criptografando e descriptografando dados
    data = "informações sensíveis"
    encrypted_data = encrypt_data(data, key)
    print(f"Dados criptografados: {encrypted_data.hex()}")
    
    decrypted_data = decrypt_data(encrypted_data, key)
    print(f"Dados descriptografados: {decrypted_data}")

    # Gerando hash dos dados
    data_hash = hash_data(data)
    print(f"Hash dos dados: {data_hash}")

    # Analisando tráfego de rede (rodando em thread separada)
    interface = "eth0"  # Altere conforme necessário
    print("Iniciando captura de pacotes na interface:", interface)
    
    packet_thread = threading.Thread(target=sniff_packets, args=(interface,))
    packet_thread.daemon = True
    packet_thread.start()

    # Simulando o tempo para captura de pacotes
    time.sleep(10)  # Captura pacotes por 10 segundos

if __name__ == "__main__":
    main()
