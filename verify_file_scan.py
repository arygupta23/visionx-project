import sys
import os

sys.path.append(r'c:\Users\gupta\OneDrive\Desktop\visionx-project')
from app import score_file

def test_file_scan():
    print("=== FILE SCAN CONTENT TEST ===")
    
    # 1. Create a dummy file content with a suspicious link
    # http://flipkart.com/ is valid but HTTP (Score 35 penalty)
    content = b"Here is a link: http://flipkart.com/"
    filename = "test_scan.txt"
    
    print(f"Scanning file content: {content}")
    
    score, reasons, sha = score_file(filename, content)
    
    print(f"Score: {score}")
    print(f"Reasons: {reasons}")
    
    # Expected: Score >= 35 (from URL) + 10 (small file) = 45 minimum.
    # Reasons should contain "Linked URL ... No HTTPS"
    
    if score >= 45 and any("Linked URL" in r for r in reasons):
        print("PASS: Insecure link detected in file.")
    else:
        print("FAIL: Insecure link NOT detected.")

if __name__ == "__main__":
    test_file_scan()
