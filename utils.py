import io
import mmap
import os
import threading
import warnings

from queue import Queue
from xml.etree import ElementTree as ET
from zipfile import ZipFile

import requests

from asn1crypto import cms
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from update_metadata_pb2 import DeltaArchiveManifest

class HttpFile(io.RawIOBase):
    def __init__(self, url, additional_headers={}, num_threads=4):
        self.url = url
        self.additional_headers = additional_headers
        self.session = requests.Session()

        resp = self.request("HEAD")
        resp.raise_for_status()
        accept_ranges = resp.headers.get("Accept-Ranges", None)
        if accept_ranges is None:
            warnings.warn("Server might not support range requests, proceeding anyway")
        elif accept_ranges != "bytes":
            raise ValueError("Server does not support byte-based range requests")

        self.size = int(resp.headers.get("Content-Length", "0"))
        self.pos = 0
        self.close_event = threading.Event()

        self.download_queue = Queue()
        self.merge_queue = Queue()
        self.workers = []
        for _ in range(num_threads):
            worker = threading.Thread(target=self._multithread_downloader, daemon=True)
            worker.start()
            self.workers.append(worker)
    
    def request(self, method, headers={}):
        headers.update(self.additional_headers)
        return self.session.request(method, self.url, headers=headers, stream=True)

    def close(self):
        self.session.close()
        self.close_event.set()

    def closed(self):
        return self.close_event.is_set()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
    
    def seekable(self):
        return True

    def readable(self):
        return True

    def writable(self):
        return False
    
    def seek(self, offset, whence=os.SEEK_SET):
        if whence == os.SEEK_SET:
            return self._seek_to(offset)
        elif whence == os.SEEK_CUR:
            return self._seek_to(self.pos + offset)
        elif whence == os.SEEK_END:
            return self._seek_to(self.size + offset)
        else:
            raise io.UnsupportedOperation

    def _seek_to(self, pos):
        if pos < 0 or pos > self.size:
            raise ValueError("Invalid seek operation")
        self.pos = pos
        return pos

    def readall(self):
        buffer = bytearray(self.size - self.pos)
        self.readinto(buffer)
        return buffer

    def _multithread_downloader(self):
        while not self.close_event.is_set():
            offset, length = self.download_queue.get()
            while not self.close_event.is_set() and length > 0:
                data = b""
                try:
                    start_pos = self.pos + offset
                    end_pos = start_pos + length - 1

                    resp = self.request("GET", headers={
                        "Range": f"bytes={start_pos}-{end_pos}"
                    })
                    resp.raise_for_status()
                    assert resp.status_code == 206, resp.status_code

                    for chunk in resp.iter_content(None):
                        data += chunk
                        if self.close_event.is_set():
                            return
                except (requests.ConnectionError, requests.Timeout, requests.exceptions.ChunkedEncodingError) as e:
                    warnings.warn(str(e))
                
                received_length = len(data)
                if received_length > 0:
                    self.merge_queue.put((offset, data))
                    offset += received_length
                    length -= received_length
            self.download_queue.task_done()

    def readinto(self, buffer):
        buffer_size = len(buffer)
        if self.pos >= self.size:
            raise ValueError("EOF")

        worker_chunk_size = 1024*1024
        worker_offset = 0
        while worker_offset < buffer_size:
            assigned_chunk_size = min(worker_chunk_size, buffer_size - worker_offset)
            self.download_queue.put((worker_offset, assigned_chunk_size))
            worker_offset += assigned_chunk_size
        
        bytes_read = 0
        while bytes_read < buffer_size:
            offset, data = self.merge_queue.get()
            data_length = len(data)
            buffer[offset:offset+data_length] = data
            bytes_read += data_length
            self.merge_queue.task_done()

        self.pos += buffer_size
        return buffer_size

class DeltaUpdateFile:
    def __init__(self, f):
        assert f.read(4) == b"CrAU"
        self.file_format_version = int.from_bytes(f.read(8), byteorder="big", signed=False)
        self.manifest_size = int.from_bytes(f.read(8), byteorder="big", signed=False)
        if self.file_format_version >= 2:
            self.metadata_signature_size = int.from_bytes(f.read(4), byteorder="big", signed=False)
        self.manifest = DeltaArchiveManifest()
        self.manifest.ParseFromString(f.read(self.manifest_size))

class DownloadDescriptor:
    DD_NAMESPACES = {"dd": "http://www.openmobilealliance.org/xmlns/dd"}

    def __init__(self, url):
        resp = requests.get(url)
        resp.raise_for_status()
        xml = ET.fromstring(resp.content)

        self.name = xml.find("dd:name", namespaces=self.DD_NAMESPACES).text
        self.object_uri = xml.find("dd:objectURI", namespaces=self.DD_NAMESPACES).text
        self.description = xml.find("dd:description", namespaces=self.DD_NAMESPACES).text
        self.abdd = xml.find("dd:ABDD", namespaces=self.DD_NAMESPACES).text

def load_props(prop_string):
    props = {}

    for line in prop_string.splitlines():
        if isinstance(line, bytes): line = line.decode()
        if line.startswith("#"):
            continue
        else:
            prop_key, prop_value = line.split("=", 1)
            props[prop_key] = prop_value
    return props

def redmagic_probe_full_ota_url(models, build_display_id, sw_internal_version):
    if sw_internal_version.startswith("GEN_NEEA_"):
        full_ota_prefix = "https://rom.download.nubia.com/Europe%26Asia/"
    elif sw_internal_version.startswith("GEN_EEA_"):
        full_ota_prefix = "https://rom.download.nubia.com/Europe/"
    else:
        return None

    for model in models:
        for full_ota_url in [
            # https://rom.download.nubia.com/Europe%26Asia/NX769S/GEN_NEEA_NX769SV1BV1.0.0B14MR3_SD_WO_ERA.zip
            f"{full_ota_prefix}{model}/{sw_internal_version}_SD_WO_ERA.zip",
            # https://rom.download.nubia.com/Europe/NX769S/V9.5.08/update.zip
            full_ota_prefix + f"{model}/" + "V" + ".".join(build_display_id.split(".")[:2]).replace("REDMAGICOS", "") + "." + build_display_id.split(".")[-1].split("_")[0].zfill(2) + "/update.zip",
            # https://rom.download.nubia.com/Europe%26Asia/NX769S/V10.0.4/update.zip
            full_ota_prefix + f"{model}/" + "V" + ".".join(build_display_id.split(".")[:2]).replace("REDMAGICOS", "") + "." + build_display_id.split(".")[-1].split("_")[0] + "/update.zip",
            # https://rom.download.nubia.com/Europe%26Asia/NX769S/V9.5.15/NEEA_NX769S.zip
            full_ota_prefix + f"{model}/" + "V" + ".".join(build_display_id.split(".")[:2]).replace("REDMAGICOS", "") + "." + build_display_id.split(".")[-1].split("_")[0].zfill(2) + f"/{'_'.join(sw_internal_version.split('_')[1:3]).split('V')[0]}.zip"
        ]:
            if requests.head(full_ota_url).ok:
                return full_ota_url
    return None

def verify_package(package_file, file_len, device_certs_zip_file):
    package_file.seek(file_len - 6)
    footer = package_file.read(6)

    assert footer[2:4] == b"\xff\xff", "no signature in file (no footer)"

    comment_size = int.from_bytes(footer[4:6], byteorder="little", signed=False)
    signature_start = int.from_bytes(footer[0:2], byteorder="little", signed=False)

    package_file.seek(file_len - (comment_size + 22))
    eocd = package_file.read(comment_size + 22)

    assert eocd.find(b"\x50\x4b\x05\x06") == 0, "no signature in file (bad footer)"

    assert eocd.find(b"\x50\x4b\x05\x06", 4) == -1, "EOCD marker found after start of EOCD"

    info = cms.ContentInfo.load(eocd[-signature_start:])
    assert info["content_type"].native == "signed_data", "signedData is null"
    signed_data = info["content"]
    cert = x509.load_der_x509_certificate(signed_data["certificates"][0].dump(force=True))

    sig_info = signed_data["signer_infos"][0]

    trusted = []
    with ZipFile(device_certs_zip_file, "r") as keystore:
        for entry in keystore.infolist():
            with keystore.open(entry, "r") as f:
                trusted.append(x509.load_pem_x509_certificate(f.read()))
    
    signature_key = cert.public_key()
    verified = False
    for c in trusted:
        if c.public_key() == signature_key:
            verified = True
            break
    if not verified:
        raise Exception("signature doesn't match any trusted key")

    alg = None
    if sig_info["digest_algorithm"].native["algorithm"] == "sha256":
        alg = hashes.SHA256()
    else:
        raise NotImplementedError("Unsupported digest algorithm")
    
    pad = None
    if sig_info["signature_algorithm"].native["algorithm"] == "rsassa_pkcs1v15":
        pad = padding.PKCS1v15()
    else:
        raise NotImplementedError("Unsupported signature algorithm")

    signature_key.verify(
        sig_info["signature"].native,
        mmap.mmap(package_file.fileno(), file_len - comment_size - 2),
        pad,
        alg
    )
