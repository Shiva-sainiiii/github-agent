from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import requests
import os
import base64
import json
import re
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

GITHUB_TOKEN   = os.getenv("GITHUB_TOKEN")
OPENROUTER_KEY = os.getenv("OPENROUTER_KEY")
GITHUB_USERNAME = os.getenv("GITHUB_USERNAME")

GH_HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json"
}

SYSTEM_PROMPT = f"""You are a powerful GitHub agent for user: {GITHUB_USERNAME}.

You can perform these GitHub actions by outputting EXACTLY one command per response:

1. CREATE_REPO: <repo-name>
   Example: CREATE_REPO: my-portfolio

2. DELETE_REPO: <repo-name>
   Example: DELETE_REPO: old-project

3. LIST_REPOS
   (no argument needed)

4. CREATE_FILE: {{"repo":"repo-name","path":"folder/file.html","content":"full file content here","message":"commit message"}}
   Use this to create new files. Path can include folders like src/index.js
   Always write complete, working code in content field.

5. READ_FILE: {{"repo":"repo-name","path":"file.html"}}
   Use this to read a file from a repo.

6. EDIT_FILE: {{"repo":"repo-name","path":"file.html","content":"updated full content","message":"what changed"}}
   Use this to edit/update existing files.

7. DELETE_FILE: {{"repo":"repo-name","path":"file.html","message":"reason"}}
   Use this to delete a specific file.

8. LIST_FILES: {{"repo":"repo-name","path":""}}
   Use this to list files in a repo or folder. Leave path empty for root.

IMPORTANT RULES:
- Output ONLY the command, nothing else before or after it.
- JSON must be valid — no trailing commas, proper quotes.
- For code in content field, escape double quotes as \\" and newlines as \\n.
- Always write complete working code, never truncate.
- If user asks something you can't do via GitHub API, explain it conversationally (no command).
- Remember: you have full context of the conversation above.
"""


def extract_command(text):
    """Robustly extract command from AI response."""
    text = text.strip()
    
    commands = ["CREATE_REPO:", "DELETE_REPO:", "LIST_REPOS", "CREATE_FILE:",
                "READ_FILE:", "EDIT_FILE:", "DELETE_FILE:", "LIST_FILES:"]
    
    for cmd in commands:
        if cmd in text:
            if cmd == "LIST_REPOS":
                return ("LIST_REPOS", None)
            
            parts = text.split(cmd, 1)
            if len(parts) < 2:
                continue
            value = parts[1].strip()
            
            # For JSON commands, extract just the JSON block
            if value.startswith("{"):
                brace_count = 0
                json_end = 0
                for i, ch in enumerate(value):
                    if ch == "{":
                        brace_count += 1
                    elif ch == "}":
                        brace_count -= 1
                        if brace_count == 0:
                            json_end = i + 1
                            break
                if json_end > 0:
                    value = value[:json_end]
            else:
                # For simple string commands, take first line
                value = value.split("\n")[0].strip()
            
            return (cmd.rstrip(":"), value)
    
    return (None, None)


def gh_api(method, endpoint, **kwargs):
    """Generic GitHub API caller."""
    url = f"https://api.github.com{endpoint}"
    return requests.request(method, url, headers=GH_HEADERS, **kwargs)


def get_file_sha(repo, path):
    """Get SHA of existing file (needed for updates)."""
    r = gh_api("GET", f"/repos/{GITHUB_USERNAME}/{repo}/contents/{path}")
    if r.status_code == 200:
        return r.json().get("sha")
    return None


@app.route("/")
def home():
    return send_from_directory(".", "index.html")


@app.route("/chat", methods=["POST"])
def chat():
    body = request.json or {}
    user_message = body.get("message", "").strip()
    history = body.get("history", [])   # [{role, content}, ...]

    if not user_message:
        return jsonify({"reply": "Kuch toh bol bhai 😅", "action": None})

    # Build messages with full history
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    for h in history[-10:]:   # last 10 turns max to stay in context
        messages.append({"role": h["role"], "content": h["content"]})
    messages.append({"role": "user", "content": user_message})

    # Call AI
    try:
        ai_resp = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENROUTER_KEY}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://github-agent-r7rn.onrender.com",
                "X-Title": "GitHub Agent"
            },
            json={
                "model": "google/gemini-flash-1.5",
                "messages": messages,
                "temperature": 0.2
            },
            timeout=30
        ).json()

        if "error" in ai_resp:
            return jsonify({"reply": f"AI Error: {ai_resp['error'].get('message', 'Unknown error')}", "action": "error"})

        ai_text = ai_resp["choices"][0]["message"]["content"].strip()

    except requests.Timeout:
        return jsonify({"reply": "AI ne jawab dene me bahut time lagaya. Dobara try karo 🔄", "action": "error"})
    except Exception as e:
        return jsonify({"reply": f"AI connection error: {str(e)}", "action": "error"})

    # Parse command
    cmd, value = extract_command(ai_text)

    # --- CREATE REPO ---
    if cmd == "CREATE_REPO":
        repo_name = re.sub(r"[^a-zA-Z0-9_.-]", "-", value.strip())
        r = gh_api("POST", "/user/repos", json={"name": repo_name, "private": False, "auto_init": True})
        if r.status_code == 201:
            data = r.json()
            return jsonify({
                "reply": f"✅ Repo ban gaya!\n**{repo_name}**\n🔗 {data['html_url']}",
                "action": "create_repo",
                "url": data["html_url"],
                "repo": repo_name
            })
        elif r.status_code == 422:
            return jsonify({"reply": f"⚠️ Repo `{repo_name}` already exist karta hai.", "action": "warning"})
        else:
            return jsonify({"reply": f"❌ GitHub Error: {r.json().get('message', 'Repo nahi bana')}", "action": "error"})

    # --- DELETE REPO ---
    elif cmd == "DELETE_REPO":
        repo_name = value.strip()
        r = gh_api("DELETE", f"/repos/{GITHUB_USERNAME}/{repo_name}")
        if r.status_code == 204:
            return jsonify({"reply": f"🗑️ Repo `{repo_name}` delete ho gaya.", "action": "delete_repo"})
        else:
            msg = r.json().get("message", "Repo delete nahi hua") if r.content else "Repo delete nahi hua"
            return jsonify({"reply": f"❌ Delete Error: {msg}", "action": "error"})

    # --- LIST REPOS ---
    elif cmd == "LIST_REPOS":
        r = gh_api("GET", f"/users/{GITHUB_USERNAME}/repos?per_page=20&sort=updated")
        if r.status_code == 200:
            repos = r.json()
            if not repos:
                return jsonify({"reply": "Koi repo nahi hai abhi.", "action": "list_repos", "repos": []})
            lines = [f"📁 **{rp['name']}** — ⭐{rp['stargazers_count']} — `{rp['visibility']}`\n🔗 {rp['html_url']}" for rp in repos]
            return jsonify({
                "reply": f"Tere {len(repos)} repos:\n\n" + "\n\n".join(lines),
                "action": "list_repos",
                "repos": [{"name": rp["name"], "url": rp["html_url"]} for rp in repos]
            })
        else:
            return jsonify({"reply": "❌ Repos fetch nahi hue.", "action": "error"})

    # --- LIST FILES ---
    elif cmd == "LIST_FILES":
        try:
            data = json.loads(value)
            repo = data["repo"]
            path = data.get("path", "").strip("/")
            endpoint = f"/repos/{GITHUB_USERNAME}/{repo}/contents/{path}" if path else f"/repos/{GITHUB_USERNAME}/{repo}/contents"
            r = gh_api("GET", endpoint)
            if r.status_code == 200:
                items = r.json()
                if not isinstance(items, list):
                    items = [items]
                lines = []
                for item in items:
                    icon = "📁" if item["type"] == "dir" else "📄"
                    lines.append(f"{icon} {item['path']}")
                reply = f"Files in `{repo}/{path or ''}`:\n\n" + "\n".join(lines)
                return jsonify({"reply": reply, "action": "list_files"})
            else:
                return jsonify({"reply": f"❌ Files fetch nahi hue: {r.json().get('message','')}", "action": "error"})
        except Exception as e:
            return jsonify({"reply": f"❌ Parse error: {str(e)}", "action": "error"})

    # --- READ FILE ---
    elif cmd == "READ_FILE":
        try:
            data = json.loads(value)
            repo = data["repo"]
            path = data["path"]
            r = gh_api("GET", f"/repos/{GITHUB_USERNAME}/{repo}/contents/{path}")
            if r.status_code == 200:
                file_data = r.json()
                content = base64.b64decode(file_data["content"]).decode("utf-8", errors="replace")
                preview = content[:2000] + ("\n...[truncated]" if len(content) > 2000 else "")
                return jsonify({
                    "reply": f"📄 `{path}` ({file_data['size']} bytes):\n\n```\n{preview}\n```",
                    "action": "read_file",
                    "content": content,
                    "sha": file_data["sha"]
                })
            else:
                return jsonify({"reply": f"❌ File nahi mili: {r.json().get('message','')}", "action": "error"})
        except Exception as e:
            return jsonify({"reply": f"❌ Error: {str(e)}", "action": "error"})

    # --- CREATE FILE ---
    elif cmd == "CREATE_FILE":
        try:
            data = json.loads(value)
            repo     = data["repo"]
            path     = data["path"]
            content  = data["content"]
            message  = data.get("message", f"Add {path} via AI Agent")

            content_b64 = base64.b64encode(content.encode()).decode()

            # Check if file exists to decide create vs update
            existing_sha = get_file_sha(repo, path)
            payload = {"message": message, "content": content_b64}
            if existing_sha:
                payload["sha"] = existing_sha

            r = gh_api("PUT", f"/repos/{GITHUB_USERNAME}/{repo}/contents/{path}", json=payload)
            if r.status_code in [200, 201]:
                url = r.json()["content"]["html_url"]
                action = "update_file" if existing_sha else "create_file"
                verb   = "Update" if existing_sha else "Bana"
                return jsonify({
                    "reply": f"✅ File {verb} di!\n**{path}**\n🔗 {url}",
                    "action": action,
                    "url": url
                })
            else:
                return jsonify({"reply": f"❌ GitHub Error: {r.json().get('message','File nahi bani')}", "action": "error"})
        except json.JSONDecodeError as e:
            return jsonify({"reply": f"❌ AI ne sahi JSON nahi diya. Dobara try karo.\nError: {str(e)}", "action": "error"})
        except Exception as e:
            return jsonify({"reply": f"❌ Error: {str(e)}", "action": "error"})

    # --- EDIT FILE ---
    elif cmd == "EDIT_FILE":
        try:
            data = json.loads(value)
            repo    = data["repo"]
            path    = data["path"]
            content = data["content"]
            message = data.get("message", f"Update {path} via AI Agent")

            sha = get_file_sha(repo, path)
            if not sha:
                return jsonify({"reply": f"❌ File `{path}` exist nahi karti repo `{repo}` me.", "action": "error"})

            content_b64 = base64.b64encode(content.encode()).decode()
            r = gh_api("PUT", f"/repos/{GITHUB_USERNAME}/{repo}/contents/{path}",
                       json={"message": message, "content": content_b64, "sha": sha})
            if r.status_code in [200, 201]:
                url = r.json()["content"]["html_url"]
                return jsonify({
                    "reply": f"✅ File update ho gayi!\n**{path}**\n🔗 {url}",
                    "action": "update_file",
                    "url": url
                })
            else:
                return jsonify({"reply": f"❌ Update Error: {r.json().get('message','')}", "action": "error"})
        except json.JSONDecodeError as e:
            return jsonify({"reply": f"❌ JSON parse error: {str(e)}", "action": "error"})
        except Exception as e:
            return jsonify({"reply": f"❌ Error: {str(e)}", "action": "error"})

    # --- DELETE FILE ---
    elif cmd == "DELETE_FILE":
        try:
            data    = json.loads(value)
            repo    = data["repo"]
            path    = data["path"]
            message = data.get("message", f"Delete {path} via AI Agent")

            sha = get_file_sha(repo, path)
            if not sha:
                return jsonify({"reply": f"❌ File `{path}` exist nahi karti.", "action": "error"})

            r = gh_api("DELETE", f"/repos/{GITHUB_USERNAME}/{repo}/contents/{path}",
                       json={"message": message, "sha": sha})
            if r.status_code == 200:
                return jsonify({"reply": f"🗑️ File `{path}` delete ho gayi.", "action": "delete_file"})
            else:
                return jsonify({"reply": f"❌ Delete Error: {r.json().get('message','')}", "action": "error"})
        except Exception as e:
            return jsonify({"reply": f"❌ Error: {str(e)}", "action": "error"})

    # --- Plain AI Response ---
    else:
        return jsonify({"reply": ai_text, "action": "message"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
