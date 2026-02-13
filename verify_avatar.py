import urllib.request
import urllib.parse
import json
import ssl
import os

# Ignore SSL
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

BASE_URL = "http://localhost:5000/api/users"

def run_tests():
    print("=== TESTING AVATAR UPLOAD ===")
    
    # 1. Fetch Admin User
    user_id = 1
    
    # 2. Create dummy image
    image_content = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\xff\xff?\x00\x05\xfe\x02\xfe\xdc\xcc\x59\xe7\x00\x00\x00\x00IEND\xaeB`\x82'
    boundary = '---BOUNDARY---'
    
    # Construct multipart form data
    body = []
    body.append(f'--{boundary}'.encode())
    body.append(f'Content-Disposition: form-data; name="avatar"; filename="test.png"'.encode())
    body.append(b'Content-Type: image/png')
    body.append(b'')
    body.append(image_content)
    body.append(f'--{boundary}--'.encode())
    body.append(b'')
    
    body_content = b'\r\n'.join(body)
    
    try:
        req = urllib.request.Request(
            f"{BASE_URL}/{user_id}/avatar", 
            data=body_content,
            headers={
                'Content-Type': f'multipart/form-data; boundary={boundary}',
                'Content-Length': len(body_content)
            },
            method='POST'
        )
        
        with urllib.request.urlopen(req, context=ctx) as response:
            data = json.loads(response.read().decode())
            print(f"PASS: Upload response: {data}")
            if 'avatar' not in data:
                 print("FAIL: No avatar field in response")
            else:
                 print("PASS: Avatar URL returned")
    
    except Exception as e:
        print(f"FAIL: Upload error: {e}")

if __name__ == "__main__":
    run_tests()
