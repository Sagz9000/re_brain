
import requests
import json

base_url = "http://localhost:8005"
binary_name = "cpu-z_2.14-en.exe" 

def test_get(endpoint):
    try:
        res = requests.get(f"{base_url}{endpoint}")
        print(f"GET {endpoint}: {res.status_code}")
        if res.status_code == 200:
            try:
                print(str(res.json())[:200] + "...")
            except:
                print(res.text[:200])
        else:
            print(res.text)
    except Exception as e:
        print(f"Error: {e}")
        
test_get("/binaries")
test_get(f"/binary/{binary_name}/hex?limit=16")
test_get(f"/binary/{binary_name}/functions")
