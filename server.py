from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import requests
import os
import base64
import json
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
OPENROUTER_KEY = os.getenv("OPENROUTER_KEY")
GITHUB_USERNAME = os.getenv("GITHUB_USERNAME")

@app.route('/')
def home():
    return send_from_directory('.', 'index.html')

@app.route('/chat', methods=['POST'])
def chat():
    user_message = request.json.get('message')
    
    try:
        ai_response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENROUTER_KEY}",
                "Content-Type": "application/json",
                "HTTP-Referer": "http://localhost:5000",
                "X-Title": "GitHub Agent"
            },
            json={
                "model": "nvidia/nemotron-3-super-120b-a12b:free",
                "messages": [
                    {"role": "system", "content": f"""Tu ek GitHub agent hai. User ka GitHub username: {GITHUB_USERNAME}.
                    
                    RULES:
                    1. Repo banane ke liye: CREATE_REPO: repo-name
                    2. File banane ke liye JSON: CREATE_FILE: {{"repo": "name", "filename": "file.html", "code": "poora code"}}
                    3. Repo delete karne ke liye: DELETE_REPO: repo-name
                    
                    Sirf ek command ek baar me. Poora code dena file me."""},
                    {"role": "user", "content": user_message}
                ]
            }
        ).json()
        
        if 'error' in ai_response:
            return jsonify({"reply": f"OpenRouter Error: {ai_response['error']['message']}"})
            
        ai_text = ai_response['choices'][0]['message']['content']
        
    except Exception as e:
        return jsonify({"reply": f"Error: {str(e)}"})
    
    # CREATE REPO
    if "CREATE_REPO:" in ai_text:
        repo_name = ai_text.split("CREATE_REPO:")[1].strip()
        r = requests.post(
            "https://api.github.com/user/repos",
            headers={"Authorization": f"token {GITHUB_TOKEN}"},
            json={"name": repo_name, "private": False}
        )
        if r.status_code == 201:
            return jsonify({"reply": f"Repo ban gaya bhai ✅: https://github.com/{GITHUB_USERNAME}/{repo_name}"})
        elif r.status_code == 422:
            return jsonify({"reply": f"Repo '{repo_name}' already exist karta hai."})
        else:
            return jsonify({"reply": f"GitHub Error: {r.json().get('message', 'Repo nahi bana')}"})
    
    # DELETE REPO - NAYA FEATURE
    elif "DELETE_REPO:" in ai_text:
        repo_name = ai_text.split("DELETE_REPO:")[1].strip()
        r = requests.delete(
            f"https://api.github.com/repos/{GITHUB_USERNAME}/{repo_name}",
            headers={"Authorization": f"token {GITHUB_TOKEN}"}
        )
        if r.status_code == 204:
            return jsonify({"reply": f"Repo '{repo_name}' delete ho gaya bhai 🗑️✅"})
        else:
            return jsonify({"reply": f"Delete Error: {r.json().get('message', 'Repo delete nahi hua')}"})
        
    # CREATE FILE - JSON WALA
    elif "CREATE_FILE:" in ai_text:
        try:
            json_str = ai_text.split("CREATE_FILE:")[1].strip()
            data = json.loads(json_str)
            repo_name = data['repo']
            filename = data['filename']
            code = data['code']
            
            content_b64 = base64.b64encode(code.encode()).decode()
            
            r = requests.put(
                f"https://api.github.com/repos/{GITHUB_USERNAME}/{repo_name}/contents/{filename}",
                headers={"Authorization": f"token {GITHUB_TOKEN}"},
                json={
                    "message": f"Add {filename} via AI Agent",
                    "content": content_b64
                }
            )
            if r.status_code in [200, 201]:
                return jsonify({"reply": f"File ban gayi ✅: https://github.com/{GITHUB_USERNAME}/{repo_name}/blob/main/{filename}"})
            else:
                return jsonify({"reply": f"GitHub Error: {r.json().get('message', 'File nahi bani')}"})
        except Exception as e:
            return jsonify({"reply": f"File parse error: {str(e)}"})
    
    else:
        return jsonify({"reply": ai_text})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
