
import google.generativeai as genai
import os
import json

# Load settings
try:
    with open('/data/settings.json', 'r') as f:
        settings = json.load(f)
    api_key = settings.get('gemini_api_key')
except Exception as e:
    print(f"Error loading settings: {e}")
    exit(1)

if not api_key:
    print("No API Key found")
    exit(1)

genai.configure(api_key=api_key)

print("Available Models:")
try:
    for m in genai.list_models():
        if 'generateContent' in m.supported_generation_methods:
            print(f"- {m.name}")
except Exception as e:
    print(f"Error listing models: {e}")
