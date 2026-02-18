# Multi-Level Port Scanner

A modular port scanner project demonstrating progressive development 
from Basic TCP scanning to Advanced Stealth scanning techniques.

## Project Structure

- basic/          → Beginner TCP scanner
- intermediate/   → TCP + UDP + Banner grabbing
- professional/   → Structured output + Thread control
- advanced/       → Stealth scans (SYN, FIN, NULL, XMAS, ACK)

## Installation

pip install -r requirements.txt

## Usage Examples

Basic:
cd basic
python3 scanner.py

Intermediate:
cd intermediate
python3 scanner.py -t <target> -p 20-80 -s tcp

Professional:
cd professional
python3 scanner.py -t <target> -p 1-1000 -s tcp -th 200

Advanced:
cd advanced
sudo python3 scanner.py -t <target> -s syn -p 20-80

## Disclaimer

This tool is built for educational and authorized penetration testing purposes only.
