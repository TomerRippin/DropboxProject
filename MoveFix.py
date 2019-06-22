from __future__ import absolute_import, division, print_function, unicode_literals
import sys
import time
import zlib
from watchdog.observers import Observer
from watchdog.events import LoggingEventHandler
import os
import shutil
from hkdf import Hkdf
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Hash import (SHA1, SHA256, SHA224, SHA256, SHA384,
                         SHA512, HMAC)
import random
from base64 import urlsafe_b64encode, urlsafe_b64decode
import numpy as np
from tkinter.filedialog import askopenfilename
from tkinter import *
import tkinter as tk
from easygui import *
import hashlib
import six


def crc_compare(event):
    """
    a function that compares the original crc that in the "shadow file" to the new crc of the modified file
    :param event: watchdog event
    :return: boolean
    """
    origCRCFile = open(event.src_path + '' + '.crc32Dir' + '/' + 'crc32.32b', "r+")
    origCRC = origCRCFile.read()
    newCRC = crc(event.src_path)
    if origCRC == newCRC:
        return True
    else:
        return False

class DropboxContentHasher(object):
    """
    Computes a hash using the same algorithm that the Dropbox API uses for the
    the "content_hash" metadata field.
    The digest() method returns a raw binary representation of the hash.  The
    hexdigest() convenience method returns a hexadecimal-encoded version, which
    is what the "content_hash" metadata field uses.
    This class has the same interface as the hashers in the standard 'hashlib'
    package.
    Example:
        hasher = DropboxContentHasher()
        with open('some-file', 'rb') as f:
            while True:
                chunk = f.read(1024)  # or whatever chunk size you want
                if len(chunk) == 0:
                    break
                hasher.update(chunk)
        print(hasher.hexdigest())
    """

    BLOCK_SIZE = 4 * 1024 * 1024

    def __init__(self):
        self._overall_hasher = hashlib.sha256()
        self._block_hasher = hashlib.sha256()
        self._block_pos = 0

        self.digest_size = self._overall_hasher.digest_size
        # hashlib classes also define 'block_size', but I don't know how people use that value

    def update(self, new_data):
        if self._overall_hasher is None:
            raise AssertionError(
                "can't use this object anymore; you already called digest()")

        assert isinstance(new_data, six.binary_type), (
            "Expecting a byte string, got {!r}".format(new_data))

        new_data_pos = 0
        while new_data_pos < len(new_data):
            if self._block_pos == self.BLOCK_SIZE:
                self._overall_hasher.update(self._block_hasher.digest())
                self._block_hasher = hashlib.sha256()
                self._block_pos = 0

            space_in_block = self.BLOCK_SIZE - self._block_pos
            part = new_data[new_data_pos:(new_data_pos+space_in_block)]
            self._block_hasher.update(part)

            self._block_pos += len(part)
            new_data_pos += len(part)

    def _finish(self):
        if self._overall_hasher is None:
            raise AssertionError(
                "can't use this object anymore; you already called digest() or hexdigest()")

        if self._block_pos > 0:
            self._overall_hasher.update(self._block_hasher.digest())
            self._block_hasher = None
        h = self._overall_hasher
        self._overall_hasher = None  # Make sure we can't use this object anymore.
        return h

    def digest(self):
        return self._finish().digest()

    def hexdigest(self):
        return self._finish().hexdigest()

    def copy(self):
        c = DropboxContentHasher.__new__(DropboxContentHasher)
        c._overall_hasher = self._overall_hasher.copy()
        c._block_hasher = self._block_hasher.copy()
        c._block_pos = self._block_pos
        return c

def guiWelcomeBox():
    """
    a graphic user interface that welcomes the user
    :return: none
    """
    msg = "welcome to my Dropbox project\n " \
          "now im going to show you a demo of the project"
    title = "Tomer Rippin Dropbox project"
    msgbox(msg, title, ok_button="lets go!!")


def guiPasswordBox():
    """
    a graphic user interface function that gets a user ID and password from the user
    :return: none
    """
    msg = "Enter login information"
    title = "Please enter password"
    fieldNames = ["Password"]
    fieldValues = []  # we start with blanks for the values
    fieldValues = multpasswordbox(msg, title, fieldNames)

    # make sure that none of the fields was left blank
    while 1:
        if fieldValues == None: break
        errmsg = ""
        for i in range(len(fieldNames)):
            if fieldValues[i].strip() == "":
                errmsg = errmsg + ('"%s" is a required field.\n\n' % fieldNames[i])
        if errmsg == "": break  # no problems found
        fieldValues = multpasswordbox(errmsg, title, fieldNames, fieldValues)
    global password
    password = fieldValues[0]


def guiDecryptButton():
    """
    a graphic user interface button that calls the "choosefilefordecrypt"
    function
    :return: none
    """
    root = tk.Tk()
    frame = tk.Frame(root)
    frame.pack()

    decryptbutton = tk.Button(
        frame,
        text="decrypt",
        command=chooseFilesForDec)
    decryptbutton.pack(side=tk.LEFT)


def chooseFilesForDec():
    """
    a function that starts the decryption process
    the function starts when the user presses the "decrypt button
    it gets the filenames the user wants to decrypt, the original and the already encrypted
    it cuts the filenames to only the part "callDec" function need.
    it calls the "callDec" function
    :return: none
    """
    encFilenameInit = askopenfilename()
    currentDirectory = os.getcwd()
    delete = len(currentDirectory)
    lengthEnc = ((delete - len(encFilenameInit)))
    encFilename = "." + encFilenameInit[lengthEnc:]

    callDec(encFilename)


def callDec(encFilename):
    """
    the function creates a salt from the original file
    it calls the "decrypt" function
    :param origFilename: the original file you want to decrypt
    :param encFilename: the encrypted file
    :return:
    """
    encryptionObj.fileDecrypt(encFilename)


class MyDict:
    """  a class that responsible to all of the dictionary operations   """

    def __init__(self):
        """
        creats a dictionary file (mydict.npy) if it doesn't exists it creates one and initialize it
        """
        self.dictName = "mydict.npy"
        try:
            self.dictonary = np.load(self.dictName, allow_pickle=True).item()
        except:
            print("initialized dictionary")
            self.dictonary = {}
            np.save(self.dictName, self.dictonary, allow_pickle=True)

    def dictPush(self, filename, iv, tag, key):
        """
        the function decrypts the dictionary
        it pushes the iv and the tag to the dictionary with the filename as key
        it encrypts the dictionary
        it updates the "mydict.npy" file
        :param filename: the original name of the file that getting encrypt
        :param iv: the Initialization vector
        :param tag:
        :param key: the encryption key
        :return: none
        """
        self.dictionary = np.load(self.dictName, allow_pickle=True).item()

        self.dictionary[filename] = [iv, tag, key]
        np.save(self.dictName, self.dictionary, allow_pickle=True)

    def dictPull(self, filename):
        """
        it gets filename and returns the iv and tag from the dictionary
        that are necessary for the decryption process
        :param filename: the original filename of the encrypted filename
        :return: iv and tag (bytes)
        """

        self.dictionary = np.load(self.dictName, allow_pickle=True).item()
        iv, tag, key = self.dictionary[filename]
        np.save(self.dictName, self.dictionary, allow_pickle=True)
        return iv, tag, key

    def dictPrint(self):
        """
        prints the dictionary
        :return: none
        """
        self.dictionary = np.load(self.dictName, allow_pickle=True).item()
        print("dictionary --> ")
        print(self.dictionary)

    def dictDelete(self, event):
        """
        deletes the file that got deleted from the dictionary
        :param event: watchdog event
        :return: none
        """
        self.dictionary = np.load(self.dictName, allow_pickle=True).item()
        print(type(self.dictionary))
        del self.dictionary[event.src_path]
        print("dictionary --> ")
        print(self.dictionary)

    def dictSwitchKey(self, event):
        """
        when a file move occurs it switches the key in the dictionary to the new name of the
        moved file
        :param event: watchdog event
        :return: none
        """
        self.dictionary = np.load(self.dictName, allow_pickle=True).item()
        self.dictionary[event.dest_path] = self.dictionary.pop(event.src_path)
        print(self.dictionary)
        np.save(self.dictName, self.dictionary, allow_pickle=True)


def verifyFile(event):
    """
    checks if the event source isn't recursive or temporary
    :param event: watchdog event
    :return: boolean
    """
    return event.src_path[2] != '.' and "32b" not in event.src_path and 'EncFile' not in event.src_path and "EncCRC32" \
           not in event.src_path and 'crc32Dir' not in event.src_path and '_' not in event.src_path \
           and "npy" not in event.src_path and "DecryptedFile" not in event.src_path \
           and "plaintext" not in event.src_path and "Demo" not in event.src_path


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
    iv, ctx, tag = textEncrypt(key, m, associated_data=header_txt)
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
        m = textDecrypt(key, iv, ctx, tag, associated_data=header_txt)
        return m
    except Exception as e:
        raise ValueError(e)


def textEncrypt(key, plaintext, associated_data=''):
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


def textDecrypt(key, iv, ciphertext, tag, associated_data=''):
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

    def fileEncrypt(self, event, salt, destdir):
        """
        a method that calculates HKDF key based on salt and password
        reads the event file, encrypts it and stores the iv and the tag in the dictionary file
        then it writes the cipher text into an encrypted file
        it then creates a hash of the encrypted file

        :param event: watchdog event
        :param salt: CRC32 of the unencrypted file
        :param destdir: "shadow file" directory name str
        :return: none
        """
        print("in  fileEncrypt")
        # destdir = destdir + "/" + destdir
        kdf = Hkdf(str(salt).encode('utf8'), self.UTF8password, hash=hashlib.sha512)
        key = kdf.expand(b"context", 16)
        # add code for encryption encrypt(event, key)
        file_in = open(event.src_path, "r")
        plainText = file_in.read()
        plainText = [str(x) for x in plainText]
        plainText = ''.join(plainText).encode('utf8')
        print(plainText)
        iv, ctx, tag = textEncrypt(key, plainText)
        print("key -->" + str(key))
        print("iv -->" + str(iv))
        print("tag-->" + str(tag))
        print("ctx-->" + str(ctx))
        print(type(ctx))
        # add code to writing file into destdir
        encFile = open(destdir + "/EncFile", "wb+")
        encFile.write(ctx)
        encFile.close()
        d.dictPush(event.src_path, iv, tag, key)
        encFileHash = open(destdir + "/EncHash", "w+")
        hasher = DropboxContentHasher()
        encFile = open(destdir + "/EncFile", "rb+")
        encryptedData = encFile.read()
        hasher.update(encryptedData)
        encFileHash.write(hasher.hexdigest())

    def fileDecrypt(self, filename):
        """
        a method that calculates HKDF key based on salt and password
        decrypts file event.src_path
        collects from dictionary file the iv and tag
        writes decrypted file into "plaintext"

        :param filename: the file you want to decrypt (string)

        :return:
        """
        print("in fileDecrypt")
        iv, tag, key = d.dictPull(filename[:-17])
        print("key -->" + str(key))
        print("iv -->" + str(iv))
        print("tag-->" + str(tag))

        # add code for decryption encrypt(event, key)
        file_in = open(filename, "rb")
        ctx = file_in.read()
        print(type(ctx))
        print("ctx-->" + str(ctx))
        plaintext = textDecrypt(key, iv, ctx, tag)
        print("plaintext -->" + str(plaintext))
        decryptedFile = open("./plaintext", "w+")
        decryptedFile.write(plaintext.decode("utf8"))


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
        calls the encryption

        ---

        :param event: watchdog event
        :return: none
        """
        super(MyEventHandler, self).on_created(event)

        if not event.is_directory:
            dirPath = event.src_path.split('_')[0] + '.crc32Dir'  # the name of the shadow directory
            if verifyFile(event):
                try:
                    os.mkdir(dirPath)
                except OSError:
                    print("Creation of the directory %s failed" % dirPath)
                salt = str(crc(event.src_path)).encode('UTF-8')
                encryptionObj.fileEncrypt(event, salt, dirPath)
                crcCreate(event)

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
                    if verifyFile(event):
                        d.dictSwitchKey(event)
                        shutil.move(event.src_path + '' + '.crc32Dir', event.dest_path + '.crc32Dir')

    def on_deleted(self, event):
        """
        method in MyEventHandler that gets activated whenever an 'deleted' event is
        detected by the watchdog observer

        ---
        actions

        checks the event isn't recursive or  temporary
        deletes the CRC32 directory
        deletes from the dictionary
        ---
        :param event: watchdog event
        :return: none
        """
        super(MyEventHandler, self).on_deleted(event)
        delpath = event.src_path  # a path to the src of the event
        if verifyFile(event):
            d.dictDelete(event)
            shutil.rmtree(delpath + '.crc32Dir')

    def on_modified(self, event):
        """
        method in MyEventHandler that gets activated whenever an 'modified' event is
        detected by the watchdog observer

        ---
        actions

        checks if the event that created this event is a directory or a file
        checks the event isn't recursive or  temporary
        compares the crc of the original file with the crc of the modified file
        if they are equal:
        not doing anything
        if not:
        starting the encryption process, switches the original crc with the new one

        ---
        :param event: watchdog event
        :return: none
        """
        super(MyEventHandler, self).on_modified(event)
        if len(event.src_path) > 3:
            if not event.is_directory:
                if verifyFile(event):
                    if not crc_compare(event):
                        dirPath = event.src_path + '' + '.crc32Dir'  # the name of the directory holding the CRC32 file
                        salt = str(crc(event.src_path)).encode('UTF-8')
                        encryptionObj.fileEncrypt(event, salt, dirPath)
                        d.dictPrint()
                        crcCreate(event)


if __name__ == "__main__":
    master = Tk()  # initilaize the GUI
    d = MyDict()  # creates a MyDict object
    d.__init__()
    guiWelcomeBox()
    guiPasswordBox()
    encryptionObj = MyEncryption(password)
    guiDecryptButton()
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
