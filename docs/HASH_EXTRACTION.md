# How Hash Extraction Works in nshark

When you run `nshark hashes capture.pcap`, the tool scans the packet stream for challenge-response handshakes. In these protocols, the user's plaintext password never crosses the wire—instead, the server sends a random challenge and the client replies with a hash calculated from its password and that challenge.

Because both sides of the handshake are inside the PCAP, we have everything needed to brute-force or dictionary-crack the password offline with Hashcat. Here is how `nshark` puts each hash together from raw packet bytes (`nshark/extractors/hash_extractor.py`).

---

## 1. NetNTLMv2 & NetNTLMv1 (Hashcat Modes 5600 & 5500)

Windows uses NTLMSSP for SMB file shares (port 445), HTTP NTLM logins, RPC, and WinRM. Every NTLMSSP message starts with the 8-byte ASCII signature `NTLMSSP\x00`, followed by a 4-byte little-endian message type:

1. **Type 1 (`0x01` — Negotiate):** The client connects and announces what authentication features it supports.
2. **Type 2 (`0x02` — Challenge):** The server replies with an **8-byte Server Challenge** stored at byte offset `24..32` after `NTLMSSP\x00`.
3. **Type 3 (`0x03` — Authenticate):** The client proves it knows the password by hashing its NTLM password hash with the server challenge and sending back security buffer pointers (2-byte length, 2-byte max length, 4-byte offset) for:
   - `LMResponse` (offset `12..20`)
   - `NTResponse` (offset `20..28`)
   - `DomainName` (offset `28..36`, UTF-16LE)
   - `UserName` (offset `36..44`, UTF-16LE)

### How `nshark` stitches the flow together:
Because the server challenge is in the Type 2 packet and the client response is in the Type 3 packet, `nshark` tracks active handshakes in a dictionary keyed by `(client_ip, client_port, server_ip, server_port)`:

- When it sees a **Type 2** packet from the server, it saves the 8-byte challenge hex for that connection.
- When it sees the **Type 3** packet from the client on that same connection, it slices out the UTF-16LE username and domain, then checks the length of `NTResponse`:
  - **NetNTLMv2 (`len > 24` and blob starts with `01010000`):** The first 16 bytes of `NTResponse` are the `NTProofStr` (HMAC-MD5), and the remaining bytes are the client blob (timestamp, client nonce, and target info). `nshark` outputs Hashcat Mode `5600`:
    ```text
    username::domain:ServerChallenge:NTProofStr:ClientBlob
    ```
  - **NetNTLMv1 (`len == 24`):** It slices the 24-byte LM and NT responses and outputs Hashcat Mode `5500`:
    ```text
    username::domain:LMResponse:NTResponse:ServerChallenge
    ```

---

## 2. Kerberos 5 Tickets — Kerberoasting & AS-REP Roasting (Modes 13100, 18200, 19600, 19700)

In Active Directory, Kerberos runs on port 88 (UDP and TCP). When TCP is used, Kerberos prepends a 4-byte length header before the ASN.1 payload. `nshark` inspects two message types coming back from the Domain Controller:

- **TGS-REP (ASN.1 Application Tag 13 / `0x6d`):** Service ticket replies used in **Kerberoasting**.
- **AS-REP (ASN.1 Application Tag 11 / `0x6b`):** Authentication replies used in **AS-REP Roasting** when an account has "Do not require Kerberos preauthentication" enabled.

### How `nshark` parses the ASN.1 bytes:
Rather than depending on an external ASN.1 compiler, `nshark` walks the DER Tag-Length-Value (TLV) fields directly:

1. It extracts the `GeneralString` fields (`0x1b`) to get the **Realm** (domain name), **client username**, and **Service Principal Name (SPN)** (such as `MSSQLSvc/sql01.corp.local`).
2. It finds the `EncryptedData` sequence Containing the `etype` (encryption type) and `cipher` (octet string):
   - **RC4-HMAC (`etype 23`):** The ticket was encrypted with the service or user's NTLM hash. The first 16 bytes of `cipher` are the HMAC-MD5 checksum, and the rest is the encrypted ticket body:
     - **TGS-REP (`-m 13100`):** `$krb5tgs$23$*user$realm$spn*$<first-16-bytes>$<remaining-cipher>`
     - **AS-REP (`-m 18200`):** `$krb5asrep$23$user@realm:<first-16-bytes>$<remaining-cipher>`
   - **AES-128 (`etype 17`, `-m 19600`) & AES-256 (`etype 18`, `-m 19700`):** In AES Kerberos tickets, the 12-byte HMAC checksum sits at the **end** of the cipher (`cipher[-12:]`), so `nshark` places the last 12 bytes in the checksum slot and the preceding bytes in the cipher slot.

---

## 3. HTTP & SIP Digest Authentication (Hashcat Mode 11400)

When a web server or VoIP SIP server uses Digest authentication, the server sends a `401 Unauthorized` response with a `WWW-Authenticate: Digest nonce="..."` header, and the client replies with an `Authorization: Digest ...` header.

Unlike NetNTLMv2, we don't even need to wait for the server packet because the client repeats the server's `nonce`, `realm`, `uri`, `qop`, `nc` (nonce count), and `cnonce` (client nonce) right inside its own `Authorization: Digest` header alongside the 32-character MD5 `response`.

`nshark` parses those key-value pairs from the client request, grabs the HTTP method (`GET`, `POST`, `INVITE`, etc.) from the first line of the packet, and formats the Hashcat `-m 11400` line:

```text
$sip$*<server_ip>*<port>*<user>*<realm>*<method>*http*<uri>*<nonce>*<cnonce>*<nc>*<qop>*MD5*<response>
```

---

## 4. Database Handshakes (PostgreSQL `-m 11100` & MySQL `-m 11200`)

`nshark` also watches database login flows using the same challenge-response pairing approach:

- **PostgreSQL (port 5432):** Captures the username from the client `StartupMessage`, the 4-byte salt from the server `AuthenticationMD5Password` packet (`R\x00\x00\x00\x0c\x00\x00\x00\x05<4-byte-salt>`), and the 32-char MD5 hex response from the client `PasswordMessage` (`$postgres$*user*salt*md5`).
- **MySQL (port 3306):** Captures the two-part 20-byte random scramble (salt) from the server v10 Greeting packet and pairs it with the username and 20-byte SHA1 response from the client Handshake Response (`$mysqlna$*<40-hex-salt>*<40-hex-response>`).
