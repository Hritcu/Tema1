import socket
from Crypto.Cipher import AES

iv = bytes.fromhex('3421b4422d483cce2e8ec87e1f4ffc77')
Kprim = bytes.fromhex('7bd1e82163d114915e695b8996b88f6b')
HOST = '127.0.0.1'


def decriptarecheie(cheiecriptare):
    cipher = AES.new(Kprim, AES.MODE_ECB)
    cheiedec = cipher.decrypt(cheiecriptare)
    return cheiedec


def cheiekm(mode):
    PORT = 65500

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as a:
        a.connect((HOST, PORT))

        a.sendall(bytes(mode, 'utf-8'))
        cheiecriptare = a.recv(1024)
        print(f"\nAm primit chia criptata de la KM:", cheiecriptare.hex())

        return cheiecriptare


def criptareECB(text, key):
    textcriptat = bytearray()
    bytetext = bytearray(text, 'utf-8')
    lungime = 16 - (len(bytetext) % 16)
    for i in range(lungime):
        bytetext.append(0b00000000)
    criptare = AES.new(key, AES.MODE_ECB)

    for i in range(0, len(bytetext), 16):
        block = bytes(bytetext[i: i + 16])
        blockcriptat = criptare.encrypt(block)
        textcriptat += blockcriptat

    return textcriptat


def criptareCFB(text, key):
    textcriptat = bytearray()
    bytetext = bytearray(text, 'utf-8')
    cipher = AES.new(key, AES.MODE_ECB)

    blockprecedent = cipher.encrypt(iv)
    for i in range(0, len(bytetext), 16):
        block = bytes(bytetext[i: i + 16])
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

        blockcriptat = bytes(final)
        textcriptat += blockcriptat
        blockprecedent = cipher.encrypt(blockcriptat)

    return textcriptat


def nodeB(mode, cheiecriptare):
    PORT = 63032

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as a:
        a.connect((HOST, PORT))

        a.sendall(bytes(mode, 'utf-8'))

        a.sendall(cheiecriptare)
        print("Nodul A a trimis cheia criptata catre nodul B")

        key = decriptarecheie(cheiecriptare)
        print("Cheia decriptata este:", key.hex())

        raspuns = a.recv(1024)
        print(f"Raspuns nodB: \"{raspuns.decode('utf-8')}\"")

        f = open("fisier1.txt", "r")
        text = f.read()

        if mode == "ECB":
            textcriptat = criptareECB(text, key)
        else:
            textcriptat = criptareCFB(text, key)

        a.sendall(bytes(textcriptat))
        print("Am trimis continutul fisierului criptat catre nodul B.")


def main():
    valid_input = False

    while not valid_input:
        mode = input("\nMode(ECB/CFB): ").upper()
        if mode == "ECB" or mode == "CFB":
            valid_input = True

    cheiecriptare = cheiekm(mode)
    nodeB(mode, cheiecriptare)


if __name__ == '__main__':
    main()