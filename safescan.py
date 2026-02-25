from dotenv import load_dotenv
from os import getenv
import vt

import cv2
import numpy as np
import pyzbar.pyzbar as pyzbar

load_dotenv()

vt_apikey = getenv('VIRUSTOTAL_API_KEY')
if not vt_apikey:
    raise ValueError("VirusTotal API key not found in environment.")

def vt_scan(code):
    with vt.Client(vt_apikey) as client:
        #url_id = vt.url_id(code)
        #url = client.get_object("/urls/{}", url_id)
        
        analysis = client.scan_url(code, wait_for_completion=True)
        #print(url.last_analysis_stats)
        print(analysis.stats)
    return analysis.stats #url.last_analysis_stats 

def google_scan(code):
    pass

# test on one qr code for now
# acess the camera
cap = cv2.VideoCapture(0)
font = cv2.FONT_HERSHEY_PLAIN
scanned = False
verdict_color = (255, 255, 255)  # white
verdict = ""

# based on tutorial from Pysource @ youtube
while True:
    _, frame = cap.read()

    # detecting qr codes from the camera
    decodedObjects = pyzbar.decode(frame)

    for obj in decodedObjects:
        #print("Data", obj.data)
        #save the data into a variable
        url_str = obj.data.decode("utf-8")  # decode QR bytes

        # scanning the link for threats
        if not scanned:
            stats = vt_scan(url_str)
            if stats.get("malicious", 0) > 0:
                verdict = "MALICIOUS"
                verdict_color = (0, 0, 255)  # red
            elif stats.get("suspicious", 0) > 0:
                verdict = "SUSPICIOUS"
                verdict_color = (0, 165, 255)  # orange
            else:
                verdict = "LIKELY SAFE"
                verdict_color = (0, 255, 0)  # green
            scanned = True
            break  # only scan first QR code for demo

        # just displaying the qrcode link for visualization
        cv2.putText(frame, url_str, (50, 50), font, 2, verdict_color, 3)

        # Display the verdict on the frame
        if verdict:
            cv2.putText(frame, verdict, (50, 100), font, 4, verdict_color, 3)

    cv2.imshow("Frame", frame)

    key = cv2.waitKey(1)
    if key == 27:
        break

cap.release()
cv2.destroyAllWindows()



# print(vt)
# print(vt.__spec__)