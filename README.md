# Digital Forensics Lab Reports

Technical digital forensics examination reports produced from hands-on case study work, covering raw disk/file-system analysis, file carving, steganography, and network traffic forensics.

**Examiner:** Iliya Dehghani

## Contents

| Project | Topic | Report |
|---|---|---|
| Project 1 | Employee Sabotage — USB drive FAT32 hex-level analysis, manual file carving, extension masking, steganography | [Project-1-Employee-Sabotage](Project-1-Employee-Sabotage/report.md) |
| Project 2 | Rhino Hunt (DFRWS 2005 "Rodeo") — USB image carving (Scalpel/Autopsy), FTP/Telnet/IMAP network traffic analysis, cross-evidence linking, steganography | [Project-2-Rhino-Hunt](Project-2-Rhino-Hunt/report.md) |

## Structure

Each project directory contains:
- `report.md` — the full examination report (introduction, objectives, tools, methodology, analysis, findings, chain of custody, references)
- `images/` — screenshots/figures referenced in that report, extracted from the original submissions

## Case Summaries

**Project 1 — Employee Sabotage:** A USB drive seized during an industrial espionage arrest was examined at the raw hex level (MBR, boot sector/BPB, FAT32 directory structure) using Ghex, `dd`, and `xxd` on Kali Linux — with no automated forensic suite. Four files were manually carved by directly calculating cluster offsets, two of which were deliberately mislabeled by file extension (a ZIP archive disguised as `.mp3`, a BMP disguised as `.jpg`). The recovered BMP contained a steganographically hidden list of company bid offers, extracted using a password located in the file system's volume slack.

**Project 2 — Rhino Hunt:** Based on the DFRWS 2005 "Rodeo" forensic challenge scenario, this investigation combined USB image carving (cross-validated using both Scalpel and Autopsy) with network traffic analysis across three packet captures (Telnet, FTP, IMAP, HTTP, and MSN Messenger protocols) in Wireshark. Key findings included cracked FTP archive credentials, recovered Telnet/IMAP login credentials, and — critically — a hash-matched duplicate image directly linking the seized USB drive to the network traffic, corroborated by a recovered document describing evidence destruction and concealment plans. A supplemental submission added further evidentiary linkage and an EXIF-metadata-based (though not fully tooling-confirmed) steganography finding.

## Chain of Custody

Every evidence item across both projects has a documented chain-of-custody log (start/pause/resume/completion timestamps) included at the end of its respective report, consistent with standard digital forensics evidentiary handling practice.
