"""Multi-protocol network file carver (HTTP, SMB2, FTP-DATA, SMTP MIME, TFTP) and cryptographic hasher (MD5 + SHA-256)."""

from __future__ import annotations

import base64
import gzip
import hashlib
import logging
import os
import re
import struct
import zlib
from typing import Optional

from nshark.core.models import CarvedFile, Flow, ParsedPacket

logger = logging.getLogger(__name__)

MAGIC_SIGNATURES: list[tuple[bytes, str, str]] = [
    (b"%PDF-", "PDF Document", ".pdf"),
    (b"MZ", "Windows PE Executable", ".exe"),
    (b"\x7fELF", "Linux ELF Executable", ".elf"),
    (b"PK\x03\x04", "ZIP Archive / Office OpenXML", ".zip"),
    (b"\x89PNG\r\n\x1a\n", "PNG Image", ".png"),
    (b"\xff\xd8\xff", "JPEG Image", ".jpg"),
    (b"GIF87a", "GIF Image", ".gif"),
    (b"GIF89a", "GIF Image", ".gif"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2 Compound Document (Office)", ".doc"),
    (b"\x1f\x8b\x08", "GZIP Archive", ".gz"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip Archive", ".7z"),
    (b"Rar!\x1a\x07", "RAR Archive", ".rar"),
    (b"\xfd7zXZ\x00", "XZ Archive", ".xz"),
    (b"BZh", "BZIP2 Archive", ".bz2"),
    (b"SQLite format 3\x00", "SQLite 3 Database", ".sqlite"),
    (b"\xca\xfe\xba\xbe", "Java Class Bytecode", ".class"),
    (b"\xcf\xfa\xed\xfe", "macOS Mach-O 64-bit Binary", ".macho"),
    (b"\xfe\xed\xfa\xcf", "macOS Mach-O 64-bit Binary", ".macho"),
    (b"\x4c\x00\x00\x00\x01\x14\x02\x00", "Windows Shortcut (LNK)", ".lnk"),
    (b"<?php", "PHP Script / Webshell", ".php"),
    (b"#!/bin/bash", "Bash Shell Script", ".sh"),
    (b"#!/bin/sh", "POSIX Shell Script", ".sh"),
]

CONTENT_DISP_RE = re.compile(r'filename="?([^";\r\n]+)"?', re.IGNORECASE)
CONTENT_TYPE_RE = re.compile(r"^Content-Type:\s*([^\r\n;]+)", re.IGNORECASE | re.MULTILINE)
CONTENT_ENC_RE = re.compile(r"^Content-Encoding:\s*([^\r\n;]+)", re.IGNORECASE | re.MULTILINE)
TRANSFER_ENC_RE = re.compile(r"^Transfer-Encoding:\s*([^\r\n;]+)", re.IGNORECASE | re.MULTILINE)
CONTENT_LEN_RE = re.compile(r"^Content-Length:\s*(\d+)", re.IGNORECASE | re.MULTILINE)
HTTP_GET_PATH_RE = re.compile(r"^(?:GET|POST|PUT)\s+/([^\s?#]+)", re.IGNORECASE)
MULTIPART_BOUNDARY_RE = re.compile(r"Content-Type:\s*multipart/form-data;\s*boundary=([^\r\n;\"']+)", re.IGNORECASE)
FTP_CMD_FILE_RE = re.compile(r"^(?:RETR|STOR)\s+([^\r\n]+)", re.IGNORECASE | re.MULTILINE)
MIME_ATTACHMENT_RE = re.compile(
    r"Content-(?:Disposition|Type):[^\r\n]*(?:filename|name)=\"?([^\"\r\n;]+)\"?.*?"
    r"Content-Transfer-Encoding:\s*base64\s*\r?\n\r?\n([A-Za-z0-9+/=\r\n]+)",
    re.IGNORECASE | re.DOTALL,
)

SKIP_TEXT_TYPES = {
    "text/html",
    "text/plain",
    "text/css",
    "text/javascript",
    "text/xml",
    "application/javascript",
    "application/x-javascript",
    "application/json",
    "application/xml",
    "application/xhtml+xml",
}


def _decode_chunked(data: bytes) -> bytes:
    """Decode HTTP Transfer-Encoding: chunked body bytes."""
    out = bytearray()
    pos = 0
    total = len(data)
    while pos < total:
        line_end = data.find(b"\r\n", pos)
        if line_end == -1:
            break
        size_str = data[pos:line_end].split(b";", 1)[0].strip()
        try:
            chunk_size = int(size_str, 16)
        except ValueError:
            return data if not out else bytes(out)
        if chunk_size == 0:
            break
        chunk_start = line_end + 2
        chunk_end = chunk_start + chunk_size
        out.extend(data[chunk_start:chunk_end])
        pos = chunk_end + 2
    return bytes(out) if out else data


def detect_file_type(data: bytes) -> tuple[str, str]:
    """Identify file type and default extension from magic bytes."""
    for sig, description, ext in MAGIC_SIGNATURES:
        if data.startswith(sig):
            return description, ext
    return "Binary/Data Blob", ".bin"


def sanitize_filename(name: str) -> str:
    """Strip path traversal characters and unsafe symbols from a filename."""
    base = os.path.basename(name.strip().replace("\\", "/"))
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", base)
    return safe[:120] if safe else "carved_payload"


def compute_hashes(data: bytes) -> tuple[str, str]:
    """Compute (MD5, SHA-256) hex digests of raw bytes."""
    md5_hex = hashlib.md5(data).hexdigest()
    sha256_hex = hashlib.sha256(data).hexdigest()
    return md5_hex, sha256_hex


def _record_carved(
    data: bytes,
    filename_hint: str,
    src_ip: str,
    dst_ip: str,
    output_dir: Optional[str],
    seen_sha256: set[str],
    carved_list: list[CarvedFile],
    min_size: int = 16,
) -> None:
    """Hash, deduplicate, optionally write to disk, and append a CarvedFile."""
    if len(data) < min_size:
        return
    md5_hash, sha256_hash = compute_hashes(data)
    if sha256_hash in seen_sha256:
        return
    seen_sha256.add(sha256_hash)

    file_type, default_ext = detect_file_type(data)
    if filename_hint:
        filename = sanitize_filename(filename_hint)
    else:
        filename = f"carved_{sha256_hash[:10]}{default_ext}"

    saved_path = ""
    if output_dir:
        saved_path = os.path.join(output_dir, filename)
        try:
            with open(saved_path, "wb") as fh:
                fh.write(data)
        except OSError as exc:
            logger.warning("Failed to write carved file %s: %s", saved_path, exc)

    carved_list.append(
        CarvedFile(
            filename=filename,
            file_type=file_type,
            size=len(data),
            md5=md5_hash,
            sha256=sha256_hash,
            source_ip=src_ip,
            destination_ip=dst_ip,
            extraction_path=saved_path,
        )
    )


def _extract_smb2_files(
    flow: Flow,
    output_dir: Optional[str],
    seen_sha256: set[str],
    carved: list[CarvedFile],
) -> None:
    """Extract files transferred over SMB2 CREATE + WRITE / READ commands."""
    last_smb_filename = ""
    smb_write_buf = bytearray()
    smb_src = flow.src_ip
    smb_dst = flow.dst_ip

    for pkt in flow.packets:
        payload = pkt.payload
        if not payload or b"\xfeSMB" not in payload:
            continue

        idx = payload.find(b"\xfeSMB")
        smb = payload[idx:]
        if len(smb) < 64:
            continue

        cmd = struct.unpack("<H", smb[12:14])[0]
        flags = struct.unpack("<I", smb[16:20])[0]
        is_response = bool(flags & 0x00000001)

        # SMB2 CREATE Request (cmd == 0x0005): extract UTF-16LE filename
        if cmd == 0x0005 and not is_response and len(smb) >= 120:
            name_offset = struct.unpack("<H", smb[64 + 44 : 64 + 46])[0]
            name_length = struct.unpack("<H", smb[64 + 46 : 64 + 48])[0]
            if 64 <= name_offset < len(smb) and 0 < name_length <= 512 and name_offset + name_length <= len(smb):
                raw_name = smb[name_offset : name_offset + name_length].decode("utf-16le", errors="ignore").strip("\x00\\/")
                if raw_name and "." in raw_name:
                    # Flush any previous buffered file before switching filename
                    if smb_write_buf:
                        _record_carved(bytes(smb_write_buf), last_smb_filename, smb_src, smb_dst, output_dir, seen_sha256, carved)
                        smb_write_buf.clear()
                    last_smb_filename = os.path.basename(raw_name.replace("\\", "/"))

        # SMB2 WRITE Request (cmd == 0x0009): body starts at data_offset (uint16 at smb[64+2])
        elif cmd == 0x0009 and not is_response and len(smb) >= 112:
            data_offset = struct.unpack("<H", smb[66:68])[0]
            data_length = struct.unpack("<I", smb[68:72])[0]
            if 64 <= data_offset < len(smb) and data_length > 0:
                chunk = smb[data_offset : min(len(smb), data_offset + data_length)]
                smb_write_buf.extend(chunk)
                smb_src, smb_dst = pkt.src_ip, pkt.dst_ip

        # SMB2 READ Response (cmd == 0x0008, response == True): body at data_offset (uint8 at smb[64+2])
        elif cmd == 0x0008 and is_response and len(smb) >= 80:
            data_offset = smb[66]
            data_length = struct.unpack("<I", smb[68:72])[0]
            if 64 <= data_offset < len(smb) and data_length > 0:
                chunk = smb[data_offset : min(len(smb), data_offset + data_length)]
                smb_write_buf.extend(chunk)
                smb_src, smb_dst = pkt.src_ip, pkt.dst_ip

    if smb_write_buf:
        _record_carved(bytes(smb_write_buf), last_smb_filename or "smb_transfer.bin", smb_src, smb_dst, output_dir, seen_sha256, carved)


def carve_files(
    packets: list[ParsedPacket],
    flows: list[Flow],
    output_dir: Optional[str] = None,
) -> list[CarvedFile]:
    """Carve files transferred over HTTP (GET/POST), SMB2, FTP-DATA, SMTP MIME, and TFTP.

    Args:
        packets: List of parsed packets.
        flows: Reconstructed bidirectional flows.
        output_dir: Optional directory to write extracted files to disk.

    Returns:
        List of CarvedFile objects with MD5/SHA-256 hashes and metadata.
    """
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    carved: list[CarvedFile] = []
    seen_sha256: set[str] = set()

    # 1. Track FTP control channel RETR / STOR filenames per host pair
    ftp_filenames: dict[tuple[str, str], str] = {}
    for pkt in packets:
        if pkt.protocol == "TCP" and (pkt.dst_port == 21 or pkt.src_port == 21) and pkt.payload:
            txt = pkt.payload.decode("latin-1", errors="ignore")
            m = FTP_CMD_FILE_RE.search(txt)
            if m:
                fname = sanitize_filename(m.group(1).strip())
                ftp_filenames[(pkt.src_ip, pkt.dst_ip)] = fname
                ftp_filenames[(pkt.dst_ip, pkt.src_ip)] = fname

    for flow in flows:
        # ------------------------------------------------------------------
        # A. TFTP (UDP 69 or ephemeral TFTP DATA blocks)
        # ------------------------------------------------------------------
        if flow.protocol == "UDP":
            tftp_name = ""
            tftp_blocks: dict[int, bytes] = {}
            tftp_src, tftp_dst = flow.src_ip, flow.dst_ip
            for pkt in flow.packets:
                pay = pkt.payload
                if len(pay) < 4:
                    continue
                opcode = struct.unpack("!H", pay[:2])[0]
                if opcode in (1, 2) and b"\x00" in pay[2:]:
                    raw_fn = pay[2:].split(b"\x00", 1)[0].decode("ascii", errors="ignore")
                    if raw_fn:
                        tftp_name = sanitize_filename(raw_fn)
                elif opcode == 3:
                    block_num = struct.unpack("!H", pay[2:4])[0]
                    tftp_blocks[block_num] = pay[4:]
                    tftp_src, tftp_dst = pkt.src_ip, pkt.dst_ip
            if tftp_blocks:
                assembled = b"".join(tftp_blocks[k] for k in sorted(tftp_blocks))
                _record_carved(assembled, tftp_name or "tftp_file.bin", tftp_src, tftp_dst, output_dir, seen_sha256, carved)
            continue

        if flow.protocol != "TCP":
            continue

        # ------------------------------------------------------------------
        # B. SMB2 File Carving (TCP 445 / 139)
        # ------------------------------------------------------------------
        if flow.src_port in (445, 139) or flow.dst_port in (445, 139):
            _extract_smb2_files(flow, output_dir, seen_sha256, carved)

        # ------------------------------------------------------------------
        # C. FTP Data Channel Carving (TCP port 20 or passive data channel)
        # ------------------------------------------------------------------
        is_ftp_data_port = flow.src_port == 20 or flow.dst_port == 20
        paired_ftp_name = ftp_filenames.get((flow.src_ip, flow.dst_ip), "")
        if is_ftp_data_port or (paired_ftp_name and flow.src_port > 1024 and flow.dst_port > 1024):
            ftp_segments: list[tuple[int, int, bytes]] = []
            seen_seq: set[tuple[str, int, int]] = set()
            data_src, data_dst = flow.src_ip, flow.dst_ip
            for p_idx, pkt in enumerate(flow.packets):
                if pkt.payload:
                    seq_key = (pkt.src_ip, pkt.tcp_seq, len(pkt.payload))
                    if pkt.tcp_seq and seq_key in seen_seq:
                        continue
                    if pkt.tcp_seq:
                        seen_seq.add(seq_key)
                    ftp_segments.append((pkt.tcp_seq, p_idx, pkt.payload))
                    data_src, data_dst = pkt.src_ip, pkt.dst_ip
            if any(seg[0] > 0 for seg in ftp_segments):
                ftp_segments.sort(key=lambda seg: (seg[0], seg[1]))
            ftp_buf = b"".join(seg[2] for seg in ftp_segments)
            if len(ftp_buf) >= 16:
                _record_carved(ftp_buf, paired_ftp_name or "ftp_transfer.bin", data_src, data_dst, output_dir, seen_sha256, carved)

        # ------------------------------------------------------------------
        # D. SMTP / POP3 / IMAP MIME Base64 Attachment Carving
        # ------------------------------------------------------------------
        if {flow.src_port, flow.dst_port} & {25, 110, 143, 587}:
            full_text = b"".join(p.payload for p in flow.packets if p.payload).decode("latin-1", errors="ignore")
            for m_att in MIME_ATTACHMENT_RE.finditer(full_text):
                att_name = sanitize_filename(m_att.group(1))
                b64_blob = re.sub(r"\s+", "", m_att.group(2))
                try:
                    decoded_att = base64.b64decode(b64_blob, validate=False)
                    if len(decoded_att) >= 16:
                        _record_carved(decoded_att, att_name, flow.src_ip, flow.dst_ip, output_dir, seen_sha256, carved)
                except Exception:
                    pass

        # ------------------------------------------------------------------
        # E. HTTP Responses & Multipart POST Uploads
        # ------------------------------------------------------------------
        last_requested_name = ""
        for idx, pkt in enumerate(flow.packets):
            if not pkt.payload:
                continue

            header_preview = pkt.payload[:1024].decode("utf-8", errors="ignore")
            req_match = HTTP_GET_PATH_RE.search(header_preview)
            if req_match:
                candidate = os.path.basename(req_match.group(1))
                if "." in candidate:
                    last_requested_name = sanitize_filename(candidate)

            # Check for HTTP POST/PUT multipart file upload
            mp_match = MULTIPART_BOUNDARY_RE.search(header_preview)
            if mp_match:
                boundary = mp_match.group(1).strip().encode("latin-1", errors="ignore")
                req_stream = bytearray(pkt.payload)
                for next_pkt in flow.packets[idx + 1 :]:
                    if next_pkt.src_ip == pkt.src_ip and next_pkt.payload:
                        if next_pkt.payload.startswith((b"HTTP/1.", b"GET ", b"POST ", b"PUT ")):
                            break
                        req_stream.extend(next_pkt.payload)
                parts = bytes(req_stream).split(b"--" + boundary)
                for part in parts:
                    if b"filename=" in part and b"\r\n\r\n" in part:
                        p_hdr, p_body = part.split(b"\r\n\r\n", 1)
                        if p_body.endswith(b"\r\n"):
                            p_body = p_body[:-2]
                        fn_m = CONTENT_DISP_RE.search(p_hdr.decode("utf-8", errors="ignore"))
                        up_name = sanitize_filename(fn_m.group(1)) if fn_m else "uploaded_file.bin"
                        _record_carved(p_body, up_name, pkt.src_ip, pkt.dst_ip, output_dir, seen_sha256, carved, min_size=8)

            # Check for HTTP Response with body
            if pkt.payload.startswith((b"HTTP/1.1 200", b"HTTP/1.0 200")):
                sep_idx = pkt.payload.find(b"\r\n\r\n")
                if sep_idx == -1:
                    continue

                raw_headers = pkt.payload[:sep_idx].decode("utf-8", errors="ignore")
                body = bytearray(pkt.payload[sep_idx + 4 :])
                seen_http_seq: set[tuple[int, int]] = set()
                if pkt.tcp_seq:
                    seen_http_seq.add((pkt.tcp_seq, len(pkt.payload)))

                # Reassemble subsequent continuation packets from same server (deduplicating & sorting by tcp_seq)
                cont_segments: list[tuple[int, int, bytes]] = []
                for c_idx, next_pkt in enumerate(flow.packets[idx + 1 :]):
                    if next_pkt.src_ip == pkt.src_ip and next_pkt.payload:
                        if next_pkt.payload.startswith((b"HTTP/1.", b"GET ", b"POST ")):
                            break
                        if next_pkt.tcp_seq:
                            skey = (next_pkt.tcp_seq, len(next_pkt.payload))
                            if skey in seen_http_seq:
                                continue
                            seen_http_seq.add(skey)
                        cont_segments.append((next_pkt.tcp_seq, c_idx, next_pkt.payload))

                if any(seg[0] > 0 for seg in cont_segments):
                    cont_segments.sort(key=lambda seg: (seg[0], seg[1]))
                for _, _, seg_bytes in cont_segments:
                    body.extend(seg_bytes)

                if len(body) < 32:
                    continue

                body_bytes = bytes(body)

                cl_match = CONTENT_LEN_RE.search(raw_headers)
                if cl_match:
                    expected_len = int(cl_match.group(1))
                    if 0 < expected_len < len(body_bytes):
                        body_bytes = body_bytes[:expected_len]

                te_match = TRANSFER_ENC_RE.search(raw_headers)
                if te_match and "chunked" in te_match.group(1).lower():
                    body_bytes = _decode_chunked(body_bytes)

                ce_match = CONTENT_ENC_RE.search(raw_headers)
                content_enc = ce_match.group(1).strip().lower() if ce_match else ""
                if content_enc == "gzip" or body_bytes.startswith(b"\x1f\x8b\x08"):
                    is_explicit_gz_file = last_requested_name.lower().endswith((".gz", ".tgz"))
                    if content_enc == "gzip" or not is_explicit_gz_file:
                        try:
                            body_bytes = gzip.decompress(body_bytes)
                        except Exception:
                            try:
                                d = zlib.decompressobj(16 + zlib.MAX_WBITS)
                                decompressed = d.decompress(body_bytes)
                                if decompressed:
                                    body_bytes = decompressed
                            except Exception:
                                pass
                elif content_enc == "deflate":
                    try:
                        body_bytes = zlib.decompress(body_bytes)
                    except Exception:
                        pass

                if len(body_bytes) < 32:
                    continue

                file_type, _ = detect_file_type(body_bytes)

                # Skip plain HTML/JSON/CSS/JS responses unless they match binary magic bytes
                ct_match = CONTENT_TYPE_RE.search(raw_headers)
                content_type = ct_match.group(1).strip().lower() if ct_match else ""
                if file_type == "Binary/Data Blob" and (
                    content_type in SKIP_TEXT_TYPES or content_type.startswith("text/")
                ):
                    continue

                disp_match = CONTENT_DISP_RE.search(raw_headers)
                if disp_match:
                    hint = disp_match.group(1)
                else:
                    hint = last_requested_name

                _record_carved(body_bytes, hint, pkt.src_ip, pkt.dst_ip, output_dir, seen_sha256, carved, min_size=32)

    logger.info("Carved %d unique file(s) from network traffic", len(carved))
    return carved
