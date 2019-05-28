import sys
import time
import logging
import zlib
from watchdog.observers import Observer
from watchdog.events import FileSystemEvent
from watchdog.events import LoggingEventHandler
from watchdog.events import FileCreatedEvent
from watchdog.events import FileSystemEventHandler
import hashlib
import os
import shutil
from hkdf import hkdf_expand
from  hkdf import hkdf_extract
from hkdf import Hkdf


class MyEncryption:
    """

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

        :param event: watchdog event
        :param salt: CRC32 of the unencrypted file
        :param destdir: "shadow file" directory name str
        :return:
        """

        kdf = Hkdf(salt, self.UTF8password, hash=hashlib.sha512)
        key = kdf.expand(b"context", 16)
        # add code for encryption encrypt(event, key)
        # add code to writing file into destdir

    def decrypt(self, event, salt, destdir):
        """
        a method that calculates HKDF key based on salt and password
        decrypts file event.src_path
        writes decrypted file into destdir

        :param event: watchdog event
        :param salt: CRC32 of the unencrypted file
        :param destdir:  decrypted file directory
        :return:
        """
        salt = crc(event.src_path)
        kdf = Hkdf(salt, self.UTF8password, hash=hashlib.sha512)
        key = kdf.expand(b"context", 16)
        # add code for decryption encrypt(event, key)


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
        crcFileName = event.src_path + '.crc32Dir' + "/crc32.32b"
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
            dirPath = event.src_path + '.crc32Dir'  # the name of the directory holding the CRC32 file
            if event.src_path[2] != '.' and not event.src_path.endswith("32b"):
                try:
                    os.mkdir(dirPath)
                except OSError:
                    print("Creation of the directory %s failed" % dirPath)
                # else:
                #     print("Successfully created the directory %s " % dirPath)
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
                    if not event.src_path.endswith("32b"):
                        shutil.move(event.src_path + '.crc32Dir', event.dest_path + '.crc32Dir')

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
        if event.src_path[2] != '.' and not event.src_path.endswith("32b") and not event.src_path.endswith("crc32Dir"):
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
                    if not event.src_path.endswith("32b"):
                        crcCreate(event)


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else '.'  # path is the directory of the source
    event_handler = MyEventHandler()  # the observer event_handler is MyEventHandler
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)  # the observer will check all of the files in 'path'
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
