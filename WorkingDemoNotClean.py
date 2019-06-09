import sys
import time
import zlib
from watchdog.observers import Observer
from watchdog.events import LoggingEventHandler
import hashlib
import os
import shutil
from hkdf import Hkdf
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import (SHA1, SHA256, SHA224, SHA256, SHA384,
                         SHA512, HMAC)
import mysql.connector
import random
from base64 import urlsafe_b64encode, urlsafe_b64decode
import struct
import re
import numpy as np
from tkinter.filedialog import askopenfilename
from tkinter import *
import tkinter as tk


# def callback():
#     print("decrypt!")
#     OrigFilename = askopenfilename()
#     EncFilename = askopenfilename()
#     d.printdict()
#     print(OrigFilename)
#     (OrigFilename, EncFilename)
def getfilesforcalldec():
    OrigFilenameInit = askopenfilename()
    EncFilenameInit = askopenfilename()
    currentDirectory = os.getcwd()
    delete = len(currentDirectory)
    lengthEnc = ((delete - len(EncFilenameInit)))
    lengthOrig = ((delete - len(OrigFilenameInit)))
    OrigFilename = "."+OrigFilenameInit[lengthOrig:]
    EncFilename = "."+EncFilenameInit[lengthEnc:]
    print(OrigFilename)
    print(EncFilename)
    calldec(OrigFilename, EncFilename)

def calldec(OrigFilename, EncFilename):
        salt = str(crc(OrigFilename)).encode('UTF-8')
        enc.decrypt(EncFilename, salt)


class MyDict:

    def __init__(self):
        self.dictname = "mydict.npy"
        try:
            self.d = np.load(self.dictname, allow_pickle=True).item()
        except:
            print("file not found")
            self.d = {}
            np.save(self.dictname, self.d, allow_pickle=True)

    def dictpush(self, filename, iv, tag):
        self.d = np.load(self.dictname, allow_pickle=True).item()
        self.d = {filename:[str(iv), str(tag)]}
        np.save(self.dictname, self.d, allow_pickle=True)

    def dictpull(self, filename):
        self.d = np.load(self.dictname, allow_pickle=True).item()
        iv, tag = self.d[filename]
        iv.encode("utf8")
        tag.encode("utf8")
        # print(iv)
        # print(tag)
        np.save(self.dictname, self.d, allow_pickle=True)
        return iv, tag
    def printdict(self):
        print(self.d)

    # def dictdelete(self,event):
    #     self.d = np.load("mydict.npy", allow_pickle=True).item()



def verify_file(event):
    return event.src_path[2] != '.' and "32b" not in event.src_path and 'EncFile' not in event.src_path and "EnqCRC32" \
           not in event.src_path and 'crc32Dir' not in event.src_path and '_' not in event.src_path \
           and "npy" not in event.src_path and "DecryptedFile" not in event.src_path

HASH_ALGOS = {
    'sha1': SHA1,
    'sha224': SHA224,
    'sha256': SHA256,
    'sha384': SHA384,
    'sha512': SHA512
}
HASH_CNT = 1000  # Number of hashes to compute one SHA256 takes 15 microsec,
SALT_LENGTH = 16  # Length for the Password salt for PBKDF
HASH_ALGO = 'sha256'  # For PBKDF HMAC
IV_LENGTH = 12  # Length of GCM IV
TAG_LENGTH = 16  # Length of the GCM tag, truncate if larger than this
HASH_FUNC = HASH_ALGOS[HASH_ALGO]


def hash256(*args):
    """short function for Hashing the arguments with SHA-256"""
    assert len(args) > 0, "Should give at least 1 message"
    assert all(isinstance(m, (bytes, basestring)) for m in args), \
        "All inputs should be byte string"
    h = SHA256.new(bytes(len(args)) + bytes(args[0]) + bytes(len(args[0])))
    for m in args[1:]:
        h.update(bytes(m))
        h.update(bytes(len(m)))
    h.update(bytes(len(args)))
    return h.digest()


def hmac256(secret, m):
    return HMAC.new(key=secret, msg=m, digestmod=HASH_FUNC).digest()


def pad_pw(pw, pad_length):
    """Pad pw to a pad_length, so that it hides the length of the password in bytes."""
    assert 0 < pad_length < 256
    pw = bytes(pw)
    k = len(pw) / pad_length
    topad = pw[k * pad_length:]
    topad_len = pad_length - len(topad)
    if topad_len == 0:
        topad_len = pad_length
    pad = chr(topad_len) * topad_len
    return pw + pad
    # padder = padding.PKCS7(pad_length*8).padder()
    # return padder.update(bytes(pw)) + padder.finalize()


def unpad_pw(padded_pw, pad_length):
    """Unpad pw"""
    padded_pw = bytes(padded_pw)
    padlen = ord(padded_pw[-1])
    assert padlen > 0, "Malformed padding. Last byte cannot be zero."
    pad = padded_pw[-padlen:]
    assert all((padi == chr(padlen) for padi in pad))
    return padded_pw[:-padlen]

    # unpadder = padding.PKCS7(pad_length*8).unpadder()
    # unpadder.update(bytes(pw)) + unpadder.finalize()


def pwencrypt(pw, m):
    """Encrypt the message m under pw using AES-GCM method (AEAD scheme).
    iv = 0   # Promise me you will never reuse the key
    c = <hash_style>.<iteration>.<urlsafe-base64 <salt><iv><tag><ctx>>
    :hash_style: sha-256 or sha-512, scrypt
    :iteration: Number of iteration. These two are the parameters
    for PBKDF2.
    Size of the ciphertext:
    """
    m = m.encode('ascii', errors='ignore')
    itercnt = random.randint(HASH_CNT, 2 * HASH_CNT)
    header_txt = HASH_ALGO + '.' + str(itercnt)
    sa = os.urandom(SALT_LENGTH)
    key = PBKDF2(
        pw, sa,
        dkLen=16,
        count=itercnt,
        prf=hmac256

    )
    iv, ctx, tag = _encrypt(key, m, associated_data=header_txt)
    # Salt (SALT_LENGTH), IV (IV_LENGTH), TAG (TAG_LENGTH)
    ctx_b64 = urlsafe_b64encode(sa + iv + tag + ctx)
    return header_txt + '.' + ctx_b64


def pwdecrypt(pw, full_ctx_b64):
    """
    Decrypt a ciphertext using pw,
    Recover, hash algo, iteration count, and salt, iv, tag, ctx from ctx_b64
    """
    full_ctx_b64 = full_ctx_b64.encode('ascii', errors='ignore')
    hash_algo, itercnt, ctx_b64 = full_ctx_b64.split('.')
    header_txt = hash_algo + '.' + itercnt
    ctx_bin = urlsafe_b64decode(ctx_b64)
    sa, ctx_bin = ctx_bin[:SALT_LENGTH], ctx_bin[SALT_LENGTH:]
    iv, ctx_bin = ctx_bin[:IV_LENGTH], ctx_bin[IV_LENGTH:]
    tag, ctx = ctx_bin[:TAG_LENGTH], ctx_bin[TAG_LENGTH:]
    hmac_tmp = lambda secret, m: HMAC.new(key=secret, msg=m, digestmod=HASH_ALGOS[hash_algo]).digest()
    key = PBKDF2(
        pw, sa,
        dkLen=16,
        count=int(itercnt),
        prf=hmac_tmp
    )
    try:
        m = _decrypt(key, iv, ctx, tag, associated_data=header_txt)
        return m
    except Exception as e:
        raise ValueError(e)


def _encrypt(key, plaintext, associated_data=''):
    # Generate a random 96-bit IV.
    iv = os.urandom(IV_LENGTH)
    # 16 (AES-128), 24 (AES-192), or 32 (AES-256)
    if len(key) not in (16, 24, 32):
        key = hash256(key)  # makes it 256-bit
    # Construct an AES-GCM Cipher object with the given key and a
    # randomly generated IV.
    # create the ciphertext
    encryptor = AES.new(key=key, mode=AES.MODE_GCM, nonce=iv)

    # associated_data will be authenticated but not encrypted,
    # it must also be passed in on decryption.
    encryptor.update(associated_data)

    ctx = encryptor.encrypt(plaintext)
    # Encrypt the plaintext and get the associated ciphertext.
    # GCM does not require padding.
    tag = encryptor.digest()
    return (iv, ctx, tag)


def _decrypt(key, iv, ciphertext, tag, associated_data=''):
    # Construct a Cipher object, with the key, iv, and additionally the
    # GCM tag used for authenticating the message.
    if len(key) not in (16, 24, 32):
        key = hash256(key)  # makes it 256-bit

    decryptor = AES.new(key=key, mode=AES.MODE_GCM, nonce=iv)

    # We put associated_data back in or the tag will fail to verify
    # when we finalize the decryptor.
    decryptor.update(associated_data)
    plaintext = decryptor.decrypt(ciphertext)

    # Decryption gets us the authenticated plaintext.
    # If the tag does not match an InvalidTag exception will be raised.
    decryptor.verify(tag)
    return plaintext


class MyEncryption:
    """
    a class for encryption and decryption
    """

    def __init__(self, password):
        """

        :param password:
        """
        self.password = password
        self.UTF8password = password.encode('UTF-8')

    def encrypt(self, event, salt, destdir):
        """
        a method that calculates HKDF key based on salt and password
        encrypts file event.src_path
        writes encrypted file into destdir
        inserts into the files database the filename, iv and tag
        for using them in the decryption
        :param event: watchdog event
        :param salt: CRC32 of the unencrypted file
        :param destdir: "shadow file" directory name str
        :param cursor: files database cursor
        :return:
        """
        print("in  encrypt")
        print("salt -->"+str(salt))
        destdir = destdir + "/" + destdir
        kdf = Hkdf(str(salt).encode('utf8'), self.UTF8password, hash=hashlib.sha512)
        key = kdf.expand(b"context", 16)
        # add code for encryption encrypt(event, key)
        file_in = open(event.src_path, "r")
        plainText = file_in.read()
        plainText = [str(x) for x in plainText]
        plainText = ''.join(plainText).encode('utf8')
        print(plainText)
        iv, ctx, tag = _encrypt(key, plainText)
        print("key -->" + str(key))
        print("iv -->" + str(iv))
        print("tag-->" + str(tag))
        print("ctx-->" + str(ctx))
        print(type(ctx))
        # add code to writing file into destdir
        e = open(destdir + ".EncFile", "wb+")
        e.write(ctx)
        global tagglob
        global ivglob
        tagglob = tag
        ivglob = iv
        d.dictpush(event.src_path, iv, tag)
        file_outCRC = open(destdir + ".EnqCRC32", "w+")
        file_outCRC.write(crc(destdir + ".EncFile"))

    def decrypt(self, filename, salt):
        """
        a method that calculates HKDF key based on salt and password
        decrypts file event.src_path
        collects from files database the iv and tag
        writes decrypted file into destdir

        :param event: watchdog event
        :param salt: CRC32 of the unencrypted file
        :param destdir:  decrypted file directory
        :return:
        """
        print("in decrypt")
        print("salt -->"+str(salt))
        kdf = Hkdf(str(salt).encode('utf8'), self.UTF8password, hash=hashlib.sha512)
        key = kdf.expand(b"context", 16)
        iv, tag = d.dictpull(filename[:-32])
        print("key -->" + str(key))
        print("iv -->" + str(iv))
        print("tag-->" + str(tag))
        print("tagglob -->"+str(tagglob))
        print("ivglob -->"+str(ivglob))
        ivb = iv.encode('utf8')
        tagb = tag.encode('utf8')
        # add code for decryption encrypt(event, key)
        file_in = open(filename, "rb")
        ctx = file_in.read()
        # file_in = open(filename, "r")
        # ctx = [file_in.read(x) for x in (16, 16, -1)]
        # ctx = file_in.read()
        # ctx = [str(x) for x in ctx]
        # ctx = ''.join(ctx).encode('utf8')
        # ctx1 = ctx.decode('utf8')
        # ctx1length = len(ctx1)
        # ctx2 = ctx[1:ctx1length-1]
        print(type(ctx))
        # print(type(ctx1))
        # print(type(ctx2))
        # ctxb = ctx[0]
        print("ctx-->" + str(ctx))
        # print("ctx1-->" + str(ctx1))
        # print("ctx2-->" + str(ctx2))
        plaintext = _decrypt(key, ivglob, ctx, tagglob)
        # plaintext = _decrypt(key, ivb, ctx, tagb)
        print("plaintext -->"+str(plaintext))
        f3 = open("./plaintextomer", "w+")
        f3.write(plaintext.decode("utf8"))


def crcCreate(event):
    """
    a method that accepts a watchdog event and calculates a CRC32
    of the file in event.src_path
    creates a file and writes the CRC32 into it
    the file is placed into the "shadow directory" --> event.src_path + '.crc32Dir'
    :param event: watchdog event
    :return: none
    """
    try:

        crcFileName = event.src_path + '' + '.crc32Dir' + '/' + 'crc32.32b'
        f = open(crcFileName, "w+")
        f.write(crc(event.src_path))
        print(f)
        f.close()
    except:
        print("could not open file %s" % crcFileName)


def crc(fileName):
    """
    a method that calculates the CRC32 of a given file fileName
    :param fileName: string containing file name
    :return: CRC32 hexadecimal
    """
    prev = 0
    fileName.strip('_')
    for eachLine in open(fileName, "rb"):
        prev = zlib.crc32(eachLine, prev)
    return "%X" % (prev & 0xFFFFFFFF)


class MyEventHandler(LoggingEventHandler):
    """
    a new eventhandler that adds Dropbox project functionality to the watchdog.EventHandler

    """

    def on_created(self, event):
        """
        method in MyEventHandler that gets activated whenever an 'created' event is
        detected by the watchdog observer

        ---
        actions:

        checks if the event that created this event is a directory or a file
        checks the event isn't recursive or  temporary
        creates a directory named dirPath and calls the crcCreate method

        ---

        :param event: watchdog event
        :return: none
        """
        super(MyEventHandler, self).on_created(event)

        if not event.is_directory:
            dirPath = event.src_path.split('_')[0] + '.crc32Dir'  # the name of the directory holding the CRC32 file
            if verify_file(event):
                try:
                    os.mkdir(dirPath)
                except OSError:
                    print("Creation of the directory %s failed" % dirPath)
                salt = str(crc(event.src_path)).encode('UTF-8')
                enc.encrypt(event, salt, dirPath)


    def on_moved(self, event):
        """
        method in MyEventHandler that gets activated whenever an 'moved' event is
        detected by the watchdog observer

        ---
        actions
        moves the CRC32 directory of the event file from event.src_path to event.dest_path
        ---
        :param event: watchdog event
        :return: none
        """
        super(MyEventHandler, self).on_moved(event)

        if len(event.src_path) > 3:
            if event.src_path[2] != '.':
                if not event.is_directory:
                    if verify_file(event):
                        shutil.move(event.src_path + '' + '.crc32Dir', event.dest_path + '.crc32Dir')

    def on_deleted(self, event):
        """
        method in MyEventHandler that gets activated whenever an 'deleted' event is
        detected by the watchdog observer

        ---
        actions

        checks the event isn't recursive or  temporary
        deletes the CRC32 directory
        ---
        :param event: watchdog event
        :return: none
        """
        super(MyEventHandler, self).on_deleted(event)

        delpath = event.src_path  # a path to the src of the event
        if verify_file(event):
            shutil.rmtree(delpath + '.crc32Dir')

    def on_modified(self, event):
        """
        method in MyEventHandler that gets activated whenever an 'modified' event is
        detected by the watchdog observer

        ---
        actions

        checks if the event that created this event is a directory or a file
        checks the event isn't recursive or  temporary
        calls the crcCreate method
        ---
        :param event: watchdog event
        :return: none
        """
        super(MyEventHandler, self).on_modified(event)
        if len(event.src_path) > 3:
            if event.src_path[2] != '.':
                if not event.is_directory:
                    if verify_file(event):
                        crcCreate(event)
                        dirPath = event.src_path + '' + '.crc32Dir'  # the name of the directory holding the CRC32 file
                        salt = str(crc(event.src_path)).encode('UTF-8')
                        enc.encrypt(event, salt, dirPath)


if __name__ == "__main__":
    master = Tk()
    d = MyDict()
    d.__init__()
    d.printdict()
    password = 'omertokpan1632205'
    enc = MyEncryption(password)

    root = tk.Tk()
    frame = tk.Frame(root)
    frame.pack()

    # button = tk.Button(frame,
    #                    text="Quit",
    #                    fg="red",
    #                    command=quit)
    # button.pack(side=tk.LEFT)
    decryptbutton = tk.Button(
        frame,
        text="decrypt",
        command=getfilesforcalldec)
    decryptbutton.pack(side=tk.LEFT)

    # getfilesforcalldec()
    path = sys.argv[1] if len(sys.argv) > 1 else '.'  # path is the directory of the source
    event_handler = MyEventHandler()  # the observer event_handler is MyEventHandler
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)  # the observer will check all of the files in 'path'
    observer.start()
    root = mainloop()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# in  encrypt
# salt -->b'87110519'
# b"b'gchcjvjhfytffwef'b'fefe'b''"
# key -->b'\x0b\xc9S\xad\x85a\x01"\xf9\x84\xb0\xf28\xec\x9b\x92'
# iv -->b'{\xe2yJ\xc3\x94\x80\x956m\xa9\xa2'
# tag-->b't\xf2e\x01\tNQO`\xd4\xaa\xd1\xb1XL|'
# ctx-->b"\x0fG\x02\x81n\x96}Tn$\x83\xb6JeW'\t\x19gv\x19\xc4\xc5\xb6\x88rA\xd2\xbf"
# <class 'bytes'>


# in decrypt
# salt -->b'87110519'
# key -->b'\x0b\xc9S\xad\x85a\x01"\xf9\x84\xb0\xf28\xec\x9b\x92'
# iv -->b'{\xe2yJ\xc3\x94\x80\x956m\xa9\xa2'
# tag-->b't\xf2e\x01\tNQO`\xd4\xaa\xd1\xb1XL|'
# <class 'bytes'>
# ctx-->b"\x0fG\x02\x81n\x96}Tn$\x83\xb6JeW'\t\x19gv\x19\xc4\xc5\xb6\x88rA\xd2\xbf"
