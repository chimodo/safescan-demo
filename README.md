# SafeScan QR Demo
SafeScan is a proof-of-concept QR code scanner that uses VirusTotal to evaluate the safety of URLs. It integrates OpenCV for camera access and pyzbar for QR code decoding.

This demo is intended to showcase the workflow for scanning QR codes in real time, checking the associated links against VirusTotal, and providing a simple visual verdict.

## Features
Webcam Access: Detect QR codes in real time using your camera.

URL Decoding: Extract URLs automatically from scanned QR codes.

VirusTotal API Integration: Submit URLs to check for malicious or suspicious content.

Real-time Verdicts: Displayed directly on the video feed:

🔴 Red: Malicious

🟠 Orange: Suspicious

🟢 Green: Likely safe

## How It Works
Camera Capture: OpenCV captures frames from your webcam.

QR Detection: pyzbar scans each frame for QR codes.

VirusTotal Scan: The first detected QR code is sent to VirusTotal for analysis via vt-py.

Verdict Display: The scan results are displayed on the video feed in real time.

Single Scan Per Run: Only the first QR code scanned is checked, even if more are shown.

## How to Run
### 1. Clone the repository
``Bash
git clone <your-repo-url>
cd <repo-folder>``
### 2. Install dependencies
``Bash
python -m pip install -r requirements.txt``
### 3. Environment Setup
Create a .env file in the project root and add your VirusTotal API key:

``Plaintext
VIRUSTOTAL_API_KEY=your_api_key_here``
### 4. Run the demo script
``Bash
python safescan.py``
Show a QR code to the camera; the verdict will appear on the video feed. Press ESC to exit.

## Limitations
Only scans one QR code per run. Additional codes in the same session are ignored.

Does not queue multiple scans. Sending too many URLs quickly may hit VirusTotal API rate limits but if you're a rich fancy pants and get the premium api then feel free. This is a work in progress and more services like google safebrowsing will be added to rectify the rate limitation issue and make the verdict more accurate.

Video warnings from OpenCV or pyzbar may appear but do not affect functionality.

Premium VirusTotal features like file downloads, LiveHunt, or Retrohunt are not implemented.
