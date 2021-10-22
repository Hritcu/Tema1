import socket
from Crypto.Cipher import AES

iv = bytes.fromhex('3421b4422d483cce2e8ec87e1f4ffc77')
Kprim = bytes.fromhex('7bd1e82163d114915e695b8996b88f6b')


def decriptarecheie(cheiecriptare):
    cipher = AES.new(Kprim, AES.MODE_ECB)
    cheiedec = cipher.decrypt(cheiecriptare)
    return cheiedec


def decriptareECB(textcriptat, key):
    textdecriptat = bytearray()
    cipher_dec = AES.new(key, AES.MODE_ECB)

    for i in range(0, len(textcriptat), 16):
        block = bytes(textcriptat[i: i + 16])
        dec_block = cipher_dec.decrypt(block)
        textdecriptat += dec_block

    unpad(textdecriptat)
    return textdecriptat.decode('utf-8')


def unpad(text):
    for byte in reversed(text):
        if byte == 0b00000000:
            text.remove(byte)
        else:
            return


def decriptareCFB(textcriptat, key):
    cipher = AES.new(key, AES.MODE_ECB)
    textdecriptat = bytearray()

    blockprecedent = cipher.encrypt(iv)
    for i in range(0, len(textcriptat), 16):
        block = bytes(textcriptat[i: i + 16])
        if len(blockprecedent) >= len(block):
            minblock, maxblock = block, blockprecedent
            minlen, maxlen = len(block), len(blockprecedent)

        else:
            minblock, maxblock = blockprecedent, block
            minlen, maxlen = len(blockprecedent), len(block)
        final = bytearray()
        for i in range(minlen):
            byte = minblock[i] ^ maxblock[i]
            final.append(byte)

        for i in range(minlen, maxlen):
            final.append(maxblock[i])

        dec_block = bytes(final)
        textdecriptat += dec_block
        blockprecedent = cipher.encrypt(block)

    unpad(textdecriptat)
    return textdecriptat.decode('utf-8')


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as a:
        a.bind(('127.0.0.1', 63032))
        a.listen()
        connection, addr = a.accept()
        with connection:

            mode = connection.recv(1024)
            mode = mode.decode('utf-8')
            print("\nmodul:", mode)
            connection.sendall(b'ok')

            cheiecriptata = connection.recv(1024)
            print(f"cheia criptata de la A:", cheiecriptata.hex())

            key = decriptarecheie(cheiecriptata)
            print("cheia decriptata:", key.hex())

            connection.sendall(b'Send file')

            textcriptat = connection.recv(10240)
            print("\nmesaj de la A:")
            print(textcriptat.hex())

            if mode == "ECB":
                textdecriptat = decriptareECB(textcriptat, key)
            else:
                textdecriptat = decriptareCFB(textcriptat, key)

            print(f"\ndecriptare:")
            print(textdecriptat)


if __name__ == '__main__':
    main()