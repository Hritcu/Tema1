import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

PORT = 65500
HOST = '127.0.0.1'

K = get_random_bytes(16)
K_prim = bytes.fromhex('7bd1e82163d114915e695b8996b88f6b')


def main():
    print(f"Se asteapta conectare ...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as a:
        a.bind((HOST, PORT))
        a.listen()
        conn, addr = a.accept()
        with conn:
            cipher = AES.new(K_prim, AES.MODE_ECB)
            cheiecriptata = cipher.encrypt(K)
            key_enc = cheiecriptata
            print(f"\nEncrypted K:", key_enc.hex())
            conn.sendall(key_enc)
            print("Sent encrypted key to Node A")


if __name__ == '__main__':
    main()