from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import requests
import os
import base64
import json
import re
import time
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

# ── ENV / CREDENTIALS ──
GITHUB_TOKEN    = os.getenv("GITHUB_TOKEN")
GITHUB_USERNAME = os.getenv("GITHUB_USERNAME")
OPENROUTER_KEY  = os.getenv("OPENROUTER_KEY")
VERCEL_TOKEN    = os.getenv("VERCEL_TOKEN")
RENDER_TOKEN    = os.getenv("RENDER_TOKEN")

GH_HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json"
}

VERCEL_HEADERS = {
    "Authorization": f"Bearer {VERCEL_TOKEN}",
    "Content-Type": "application/json"
}

RENDER_HEADERS = {
    "Authorization": f"Bearer {RENDER_TOKEN}",
    "Accept": "application/json",
    "Content-Type": "application/json"
}


# ════════════════════════════════════════════════════════════════
#  SECRET REDACTION — defense in depth.
#  Strips real configured secrets AND suspicious secret-shaped strings
#  from any text before it is ever sent to the client, regardless of
#  whether it came from our own code or from the AI's free-text output.
# ════════════════════════════════════════════════════════════════
_REAL_SECRETS = [s for s in [GITHUB_TOKEN, OPENROUTER_KEY, VERCEL_TOKEN, RENDER_TOKEN] if s]

# Patterns that look like real provider credentials, even if they are
# fabricated by the model rather than copied from env (catches hallucinated
# "leaks" of plausible-looking keys too).
_SECRET_PATTERNS = [
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),                 # GitHub PAT
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),         # GitHub fine-grained PAT
    re.compile(r"sk-or-v1-[A-Za-z0-9]{20,}"),            # OpenRouter
    re.compile(r"sk-[A-Za-z0-9]{20,}"),                  # OpenAI-style
    re.compile(r"Bearer\s+[A-Za-z0-9\-_\.]{15,}", re.I), # raw bearer tokens in text
    re.compile(r"rnd_[A-Za-z0-9]{20,}"),                 # Render token
]


def redact(text):
    """Remove real configured secrets and any secret-shaped strings from outbound text."""
    if not text:
        return text
    for secret in _REAL_SECRETS:
        if secret and len(secret) > 6:
            text = text.replace(secret, "[REDACTED]")
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text


def safe_jsonify(payload):
    """jsonify() wrapper that redacts every string value in the response payload
    before it leaves the server. Use this instead of jsonify() for ALL /chat responses."""
    def scrub(obj):
        if isinstance(obj, str):
            return redact(obj)
        if isinstance(obj, dict):
            return {k: scrub(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [scrub(v) for v in obj]
        return obj
    return jsonify(scrub(payload))



SYSTEM_PROMPT = f"""You are a powerful Multi-Cloud DevOps Agent for user: {GITHUB_USERNAME}.
You control three platforms: GitHub (source code), Vercel (frontend deploys), and Render (backend/web services + databases).

You act by outputting EXACTLY ONE command per response. Never combine commands. Never add commentary before or after a command.

──────────────── GITHUB COMMANDS ────────────────

1. CREATE_REPO: <repo-name>
   Example: CREATE_REPO: my-portfolio

2. DELETE_REPO: <repo-name>
   Example: DELETE_REPO: old-project

3. LIST_REPOS
   (no argument needed)

4. CREATE_FILE: {{"repo":"repo-name","path":"folder/file.html","content":"full file content here","message":"commit message"}}
   Always write complete, working code in content field.

5. READ_FILE: {{"repo":"repo-name","path":"file.html"}}

6. EDIT_FILE: {{"repo":"repo-name","path":"file.html","content":"updated full content","message":"what changed"}}

7. DELETE_FILE: {{"repo":"repo-name","path":"file.html","message":"reason"}}

8. LIST_FILES: {{"repo":"repo-name","path":""}}
   Leave path empty for root.

──────────────── VERCEL COMMANDS ────────────────

9. VERCEL_LIST_PROJECTS
   (no argument needed) — lists all Vercel projects in the account.

10. VERCEL_IMPORT_REPO: {{"repo":"repo-name","project_name":"optional-custom-name","framework":"optional-framework-preset"}}
    Connects/imports a GitHub repo as a new Vercel project. "framework" can be omitted to let Vercel auto-detect
    (e.g. "vite", "nextjs", "create-react-app", or null for static/vanilla).

11. VERCEL_DEPLOY: {{"project_name":"project-name"}}
    Triggers a new production deployment for an existing Vercel project linked to a GitHub repo.
    This waits briefly (~25s) for the build to finish. If the build is still running after that,
    you'll get a "pending" result with a deployment_id — tell the user it's still building and that
    they should ask you to check status again shortly, rather than claiming it's done.

12. VERCEL_DEPLOY_STATUS: {{"deployment_id":"dpl_xxx"}}
    Checks the status of a deployment (use the deployment_id returned by VERCEL_DEPLOY).

13. VERCEL_DELETE_PROJECT: {{"project_name":"project-name"}}
    Permanently deletes a Vercel project (all its deployments too). This does NOT delete the
    GitHub repo — only the Vercel project/connection. Ask the user to confirm if they just said
    "delete X" casually without clearly meaning the Vercel project, since this is irreversible.

──────────────── RENDER COMMANDS ────────────────

14. RENDER_LIST_SERVICES
    (no argument needed) — lists all web services, static sites, and databases on Render.

15. RENDER_GET_ENV: {{"service_id":"srv-xxx"}}
    Fetches current environment variables for a Render service.

16. RENDER_SET_ENV: {{"service_id":"srv-xxx","env_vars":{{"KEY":"value","KEY2":"value2"}}}}
    Updates/adds environment variables on a Render service (merges with existing — does not wipe unspecified keys
    unless the platform requires a full replace, in which case fetch existing first via RENDER_GET_ENV).

17. RENDER_DEPLOY: {{"service_id":"srv-xxx","clear_cache":true}}
    Triggers a manual deploy. clear_cache defaults to false if omitted.

──────────────── RULES ────────────────

- Output ONLY the command, nothing else before or after it.
- JSON must be valid — no trailing commas, proper double quotes.
- For code in content field, escape double quotes as \\" and newlines as \\n.
- Always write complete working code, never truncate.
- If the user asks something outside these 17 commands, respond conversationally with no command — explain what you can/can't do.
- You have full context of the conversation above. Use repo/project/service names mentioned earlier if the user refers back to them ("that repo", "the service", "it").
- When a user asks to "deploy X to Vercel" and X isn't a known Vercel project yet, first use VERCEL_IMPORT_REPO, then on the next turn VERCEL_DEPLOY.
- Vercel auto-deploys on every git push once a repo is imported — VERCEL_DEPLOY is only needed to force a redeploy of the current branch without a new commit. After VERCEL_IMPORT_REPO, the import itself already triggers the first deployment.

──────────────── ABSOLUTE ANTI-HALLUCINATION RULE ────────────────

You have NO knowledge of real deployment IDs, live URLs, service IDs, API keys, environment variable values, or any other infrastructure state. ALL of that only exists in the actual GitHub/Vercel/Render APIs, which you can reach ONLY by emitting one of the 17 commands above.

- NEVER write a deployment ID, project URL, service ID, status, or env var value yourself. If you don't have one of the 17 commands to run, you do not have this information — say so plainly instead of inventing it.
- NEVER format your own conversational text to look like a tool result (no fake ✅/❌ icons, no fake "Status:", "Deployment ID:", "Live URL:" labels, no fake code blocks claiming to be API output) unless you are literally emitting one of the 17 commands for the system to execute.
- NEVER output anything that resembles a real secret, token, or API key (e.g. strings starting with sk-, ghp_, vercel_, rnd_, Bearer, or long random-looking alphanumeric strings) under any circumstance, even as an example or placeholder filled with realistic-looking characters. Use literal text like <your-token-here> for placeholders.
- If you are not emitting a command, your entire response must be plain conversational text with no fabricated data points standing in for real ones.
"""


COMMANDS = [
    "CREATE_REPO:", "DELETE_REPO:", "LIST_REPOS", "CREATE_FILE:",
    "READ_FILE:", "EDIT_FILE:", "DELETE_FILE:", "LIST_FILES:",
    "VERCEL_LIST_PROJECTS", "VERCEL_IMPORT_REPO:", "VERCEL_DEPLOY:", "VERCEL_DEPLOY_STATUS:",
    "VERCEL_DELETE_PROJECT:",
    "RENDER_LIST_SERVICES", "RENDER_GET_ENV:", "RENDER_SET_ENV:", "RENDER_DEPLOY:",
]

# Commands that take no argument at all
NO_ARG_COMMANDS = {"LIST_REPOS", "VERCEL_LIST_PROJECTS", "RENDER_LIST_SERVICES"}


def looks_fabricated(text):
    """Heuristic check: does this free-text (non-command) AI response impersonate
    a real tool result instead of giving an honest conversational answer?

    This is the fallback safety net for when the model decides not to emit a real
    command but writes something that LOOKS like a deployment/status/URL result
    anyway (fabricated deployment IDs, fake 'Live URL:' lines, etc).
    """
    fabrication_markers = [
        r"deployment\s*id\s*:", r"deploy\s*id\s*:", r"dpl_[a-z0-9]{6,}",
        r"live\s*url\s*:", r"status\s*:\s*\*?\*?ready", r"srv-[a-z0-9]{6,}",
        r"trigger\s*ho\s*gaya", r"deploy\s*trigger\s*ho\s*gaya", r"successful\s*hai",
    ]
    lowered = text.lower()
    hits = sum(1 for pat in fabrication_markers if re.search(pat, lowered))
    # Two or more markers together strongly suggests the model is impersonating
    # a tool result rather than describing what it would do.
    return hits >= 2


def extract_command(text):
    """Robustly extract a single command (and its payload) from the AI response.

    Returns (command_name, raw_value_or_None). For JSON commands, raw_value_or_None
    is the raw JSON substring (still needs json.loads). For no-arg commands, value is None.
    """
    text = text.strip()

    # Sort longest-prefix-first so e.g. VERCEL_DEPLOY_STATUS: doesn't get shadowed by VERCEL_DEPLOY:
    for cmd in sorted(COMMANDS, key=len, reverse=True):
        if cmd not in text:
            continue

        bare = cmd.rstrip(":")
        if bare in NO_ARG_COMMANDS:
            return (bare, None)

        parts = text.split(cmd, 1)
        if len(parts) < 2:
            continue
        value = parts[1].strip()

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
            value = value.split("\n")[0].strip()

        return (bare, value)

    return (None, None)


# ════════════════════════════════════════════════════════════════
#  GITHUB HELPERS
# ════════════════════════════════════════════════════════════════
def gh_api(method, endpoint, **kwargs):
    url = f"https://api.github.com{endpoint}"
    return requests.request(method, url, headers=GH_HEADERS, timeout=20, **kwargs)


def get_file_sha(repo, path):
    r = gh_api("GET", f"/repos/{GITHUB_USERNAME}/{repo}/contents/{path}")
    if r.status_code == 200:
        return r.json().get("sha")
    return None


# ════════════════════════════════════════════════════════════════
#  VERCEL HELPERS
# ════════════════════════════════════════════════════════════════
def vc_api(method, endpoint, **kwargs):
    url = f"https://api.vercel.com{endpoint}"
    return requests.request(method, url, headers=VERCEL_HEADERS, timeout=20, **kwargs)


def vercel_find_project(name):
    """Find a Vercel project by name. Returns project dict or None."""
    r = vc_api("GET", "/v9/projects")
    if r.status_code != 200:
        return None
    for p in r.json().get("projects", []):
        if p.get("name") == name:
            return p
    return None


# Terminal states for a Vercel deployment — polling stops once one of these is reached.
VERCEL_TERMINAL_STATES = {"READY", "ERROR", "CANCELED"}


def vercel_poll_deployment(deployment_id, max_wait_seconds=25, interval_seconds=3):
    """Poll GET /v13/deployments/{id} until the deployment reaches a terminal readyState
    (READY, ERROR, or CANCELED) or max_wait_seconds elapses.

    max_wait_seconds is intentionally short (~25s) because this runs synchronously inside
    a single Flask request — Render's free tier, most browsers, and default WSGI worker
    timeouts will kill a request held open much longer than ~30s. Real Vercel builds often
    take 30-120+ seconds, so this will frequently time out before READY. That's expected
    and handled honestly: see "timed_out" in the return value below. The caller (VERCEL_DEPLOY)
    must report a BUILDING/in-progress status rather than success when timed_out is True, and
    the user re-checks via VERCEL_DEPLOY_STATUS (a separate, single-shot, fast request) once
    the build has had more time.

    Returns a dict: {
        "ok": bool,                # True only if readyState == READY
        "timed_out": bool,         # True if we gave up waiting before a terminal state
        "deployment": <full API response dict>,
        "state": <final readyState string>,
        "live_url": <real https:// URL from the API, or None if not ready>,
    }
    """
    elapsed = 0
    last_dep = {}
    while elapsed <= max_wait_seconds:
        r = vc_api("GET", f"/v13/deployments/{deployment_id}")
        if r.status_code != 200:
            # Transient error reaching Vercel — keep retrying until max_wait_seconds.
            time.sleep(interval_seconds)
            elapsed += interval_seconds
            continue

        dep = r.json()
        last_dep = dep
        state = dep.get("readyState", "UNKNOWN")

        if state in VERCEL_TERMINAL_STATES:
            live_url = None
            if state == "READY":
                # dep["url"] is the real unique deployment hostname assigned by Vercel
                # (e.g. "my-project-abc123xyz.vercel.app") — NEVER guessed/concatenated.
                raw_url = dep.get("url")
                if raw_url:
                    live_url = f"https://{raw_url}"
                # Prefer a production alias if one was assigned (friendlier domain),
                # but only trust it if aliasAssigned is true and alias[] is non-empty.
                if dep.get("aliasAssigned") and dep.get("alias"):
                    live_url = f"https://{dep['alias'][0]}"
            return {
                "ok": state == "READY",
                "timed_out": False,
                "deployment": dep,
                "state": state,
                "live_url": live_url,
            }

        time.sleep(interval_seconds)
        elapsed += interval_seconds

    # Gave up waiting — report this honestly rather than guessing a final state.
    return {
        "ok": False,
        "timed_out": True,
        "deployment": last_dep,
        "state": last_dep.get("readyState", "UNKNOWN"),
        "live_url": None,
    }


# ════════════════════════════════════════════════════════════════
#  RENDER HELPERS
# ════════════════════════════════════════════════════════════════
def rd_api(method, endpoint, **kwargs):
    url = f"https://api.render.com/v1{endpoint}"
    return requests.request(method, url, headers=RENDER_HEADERS, timeout=20, **kwargs)


# ════════════════════════════════════════════════════════════════
#  ROUTES
# ════════════════════════════════════════════════════════════════
@app.route("/")
def home():
    return send_from_directory(".", "index.html")


@app.route("/chat", methods=["POST"])
def chat():
    body = request.json or {}
    user_message = body.get("message", "").strip()
    history = body.get("history", [])

    if not user_message:
        return safe_jsonify({"reply": "Kuch toh bol bhai 😅", "action": None})

    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    for h in history[-10:]:
        messages.append({"role": h["role"], "content": h["content"]})
    messages.append({"role": "user", "content": user_message})

    try:
        ai_resp = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENROUTER_KEY}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://github-agent-r7rn.onrender.com",
                "X-Title": "Multi-Cloud DevOps Agent"
            },
            json={
                "model": "poolside/laguna-m.1:free",
                "messages": messages,
                "temperature": 0.2
            },
            timeout=30
        ).json()

        if "error" in ai_resp:
            return safe_jsonify({"reply": f"AI Error: {ai_resp['error'].get('message', 'Unknown error')}", "action": "error"})

        ai_text = ai_resp["choices"][0]["message"]["content"].strip()

    except requests.Timeout:
        return safe_jsonify({"reply": "AI ne jawab dene me bahut time lagaya. Dobara try karo 🔄", "action": "error"})
    except Exception as e:
        return safe_jsonify({"reply": f"AI connection error: {str(e)}", "action": "error"})

    cmd, value = extract_command(ai_text)

    # ──────────────────────────────────────────────────────────
    # GITHUB
    # ──────────────────────────────────────────────────────────
    if cmd == "CREATE_REPO":
        repo_name = re.sub(r"[^a-zA-Z0-9_.-]", "-", value.strip())
        r = gh_api("POST", "/user/repos", json={"name": repo_name, "private": False, "auto_init": True})
        if r.status_code == 201:
            data = r.json()
            return safe_jsonify({
                "reply": f"✅ Repo ban gaya!\n**{repo_name}**\n🔗 {data['html_url']}",
                "action": "create_repo", "url": data["html_url"], "repo": repo_name
            })
        elif r.status_code == 422:
            return safe_jsonify({"reply": f"⚠️ Repo `{repo_name}` already exist karta hai.", "action": "warning"})
        else:
            return safe_jsonify({"reply": f"❌ GitHub Error: {r.json().get('message', 'Repo nahi bana')}", "action": "error"})

    elif cmd == "DELETE_REPO":
        repo_name = value.strip()
        r = gh_api("DELETE", f"/repos/{GITHUB_USERNAME}/{repo_name}")
        if r.status_code == 204:
            return safe_jsonify({"reply": f"🗑️ Repo `{repo_name}` delete ho gaya.", "action": "delete_repo"})
        else:
            msg = r.json().get("message", "Repo delete nahi hua") if r.content else "Repo delete nahi hua"
            return safe_jsonify({"reply": f"❌ Delete Error: {msg}", "action": "error"})

    elif cmd == "LIST_REPOS":
        r = gh_api("GET", f"/users/{GITHUB_USERNAME}/repos?per_page=20&sort=updated")
        if r.status_code == 200:
            repos = r.json()
            if not repos:
                return safe_jsonify({"reply": "Koi repo nahi hai abhi.", "action": "list_repos", "repos": []})
            lines = [f"📁 **{rp['name']}** — ⭐{rp['stargazers_count']} — `{rp['visibility']}`\n🔗 {rp['html_url']}" for rp in repos]
            return safe_jsonify({
                "reply": f"Tere {len(repos)} repos:\n\n" + "\n\n".join(lines),
                "action": "list_repos",
                "repos": [{"name": rp["name"], "url": rp["html_url"]} for rp in repos]
            })
        else:
            return safe_jsonify({"reply": "❌ Repos fetch nahi hue.", "action": "error"})

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
                lines = [f"{'📁' if item['type'] == 'dir' else '📄'} {item['path']}" for item in items]
                reply = f"Files in `{repo}/{path or ''}`:\n\n" + "\n".join(lines)
                return safe_jsonify({"reply": reply, "action": "list_files"})
            else:
                return safe_jsonify({"reply": f"❌ Files fetch nahi hue: {r.json().get('message','')}", "action": "error"})
        except Exception as e:
            return safe_jsonify({"reply": f"❌ Parse error: {str(e)}", "action": "error"})

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
                return safe_jsonify({
                    "reply": f"📄 `{path}` ({file_data['size']} bytes):\n\n```\n{preview}\n```",
                    "action": "read_file", "content": content, "sha": file_data["sha"]
                })
            else:
                return safe_jsonify({"reply": f"❌ File nahi mili: {r.json().get('message','')}", "action": "error"})
        except Exception as e:
            return safe_jsonify({"reply": f"❌ Error: {str(e)}", "action": "error"})

    elif cmd == "CREATE_FILE":
        try:
            data = json.loads(value)
            repo, path, content = data["repo"], data["path"], data["content"]
            message = data.get("message", f"Add {path} via AI Agent")
            content_b64 = base64.b64encode(content.encode()).decode()
            existing_sha = get_file_sha(repo, path)
            payload = {"message": message, "content": content_b64}
            if existing_sha:
                payload["sha"] = existing_sha
            r = gh_api("PUT", f"/repos/{GITHUB_USERNAME}/{repo}/contents/{path}", json=payload)
            if r.status_code in [200, 201]:
                url = r.json()["content"]["html_url"]
                action = "update_file" if existing_sha else "create_file"
                verb = "Update" if existing_sha else "Bana"
                return safe_jsonify({"reply": f"✅ File {verb} di!\n**{path}**\n🔗 {url}", "action": action, "url": url, "repo": repo})
            else:
                return safe_jsonify({"reply": f"❌ GitHub Error: {r.json().get('message','File nahi bani')}", "action": "error"})
        except json.JSONDecodeError as e:
            return safe_jsonify({"reply": f"❌ AI ne sahi JSON nahi diya. Dobara try karo.\nError: {str(e)}", "action": "error"})
        except Exception as e:
            return safe_jsonify({"reply": f"❌ Error: {str(e)}", "action": "error"})

    elif cmd == "EDIT_FILE":
        try:
            data = json.loads(value)
            repo, path, content = data["repo"], data["path"], data["content"]
            message = data.get("message", f"Update {path} via AI Agent")
            sha = get_file_sha(repo, path)
            if not sha:
                return safe_jsonify({"reply": f"❌ File `{path}` exist nahi karti repo `{repo}` me.", "action": "error"})
            content_b64 = base64.b64encode(content.encode()).decode()
            r = gh_api("PUT", f"/repos/{GITHUB_USERNAME}/{repo}/contents/{path}",
                       json={"message": message, "content": content_b64, "sha": sha})
            if r.status_code in [200, 201]:
                url = r.json()["content"]["html_url"]
                return safe_jsonify({"reply": f"✅ File update ho gayi!\n**{path}**\n🔗 {url}", "action": "update_file", "url": url, "repo": repo})
            else:
                return safe_jsonify({"reply": f"❌ Update Error: {r.json().get('message','')}", "action": "error"})
        except json.JSONDecodeError as e:
            return safe_jsonify({"reply": f"❌ JSON parse error: {str(e)}", "action": "error"})
        except Exception as e:
            return safe_jsonify({"reply": f"❌ Error: {str(e)}", "action": "error"})

    elif cmd == "DELETE_FILE":
        try:
            data = json.loads(value)
            repo, path = data["repo"], data["path"]
            message = data.get("message", f"Delete {path} via AI Agent")
            sha = get_file_sha(repo, path)
            if not sha:
                return safe_jsonify({"reply": f"❌ File `{path}` exist nahi karti.", "action": "error"})
            r = gh_api("DELETE", f"/repos/{GITHUB_USERNAME}/{repo}/contents/{path}",
                       json={"message": message, "sha": sha})
            if r.status_code == 200:
                return safe_jsonify({"reply": f"🗑️ File `{path}` delete ho gayi.", "action": "delete_file"})
            else:
                return safe_jsonify({"reply": f"❌ Delete Error: {r.json().get('message','')}", "action": "error"})
        except Exception as e:
            return safe_jsonify({"reply": f"❌ Error: {str(e)}", "action": "error"})

    # ──────────────────────────────────────────────────────────
    # VERCEL
    # ──────────────────────────────────────────────────────────
    elif cmd == "VERCEL_LIST_PROJECTS":
        r = vc_api("GET", "/v9/projects")
        if r.status_code == 200:
            projects = r.json().get("projects", [])
            if not projects:
                return safe_jsonify({"reply": "Koi Vercel project nahi mila.", "action": "vercel_list", "projects": []})
            lines = []
            for p in projects:
                domain = p.get("targets", {}).get("production", {}).get("alias", [None])
                live = f"https://{p['name']}.vercel.app"
                lines.append(f"▲ **{p['name']}** — `{p.get('framework') or 'static'}`\n🔗 {live}")
            return safe_jsonify({
                "reply": f"Tere {len(projects)} Vercel projects:\n\n" + "\n\n".join(lines),
                "action": "vercel_list",
                "projects": [{"name": p["name"], "id": p["id"]} for p in projects]
            })
        else:
            return safe_jsonify({"reply": f"❌ Vercel projects fetch nahi hue: {r.text[:200]}", "action": "error"})

    elif cmd == "VERCEL_IMPORT_REPO":
        try:
            data = json.loads(value)
            repo = data["repo"]
            project_name = data.get("project_name") or repo
            framework = data.get("framework")

            payload = {
                "name": project_name,
                "gitRepository": {
                    "type": "github",
                    "repo": f"{GITHUB_USERNAME}/{repo}"
                },
                # Always set framework explicitly (null = static/vanilla if not specified).
                # Leaving this key out entirely is what caused Vercel to treat the project
                # as having unconfirmed settings, which later breaks manual /v13/deployments
                # calls with a "projectSettings required" error.
                "framework": framework if framework else None
            }

            r = vc_api("POST", "/v11/projects", json=payload)
            if r.status_code in (200, 201):
                proj = r.json()

                # Importing a project does NOT itself guarantee a finished deployment yet —
                # Vercel queues an initial build in the background. We never guess a URL here.
                # The "latestDeployments" field (if present) tells us whether one was queued.
                latest = proj.get("latestDeployments") or []
                dep_id = latest[0].get("uid") or latest[0].get("id") if latest else None

                reply = (
                    f"✅ `{repo}` Vercel se connect ho gaya!\n**Project: {proj['name']}**\n"
                    f"Project ID: `{proj.get('id')}`\n\n"
                )
                if dep_id:
                    reply += (
                        f"⏳ Vercel ne automatically ek initial build queue kar diya hai (Deployment ID: `{dep_id}`).\n"
                        f"Status check karne ke liye bol: 'check deployment status {dep_id}' — "
                        f"tabhi main real live URL bata sakta hoon, build complete hone ke baad."
                    )
                else:
                    reply += (
                        "Build abhi queue nahi hua. Deploy trigger karne ke liye bol: "
                        f"'deploy {proj['name']} to vercel'."
                    )

                return safe_jsonify({
                    "reply": reply,
                    "action": "vercel_import", "project_name": proj["name"], "project_id": proj.get("id"),
                    "deployment_id": dep_id
                })
            else:
                err = r.json().get("error", {}).get("message", r.text[:200])
                return safe_jsonify({"reply": f"❌ Vercel import Error: {err}", "action": "error"})
        except json.JSONDecodeError as e:
            return safe_jsonify({"reply": f"❌ JSON parse error: {str(e)}", "action": "error"})
        except Exception as e:
            return safe_jsonify({"reply": f"❌ Error: {str(e)}", "action": "error"})

    elif cmd == "VERCEL_DEPLOY":
        try:
            data = json.loads(value)
            project_name = data["project_name"]

            proj = vercel_find_project(project_name)
            if not proj:
                return safe_jsonify({"reply": f"❌ Vercel project `{project_name}` nahi mila. Pehle import kar.", "action": "error"})

            git_repo = proj.get("link", {})
            repo_id = git_repo.get("repoId")
            git_branch = git_repo.get("productionBranch", "main")

            if not repo_id:
                return safe_jsonify({
                    "reply": f"❌ Project `{project_name}` GitHub se linked nahi hai (no repoId). Pehle VERCEL_IMPORT_REPO se import kar.",
                    "action": "error"
                })

            # Vercel requires a "projectSettings" object on /v13/deployments whenever the
            # project doesn't already have confirmed build settings (e.g. fresh imports
            # that relied on auto-detection). We pull the framework Vercel already has on
            # file for this project and pass it back — this is the real, API-confirmed
            # value, never guessed. "null" framework is valid and means static/vanilla.
            payload = {
                "name": project_name,
                "target": "production",
                "gitSource": {
                    "type": "github",
                    "repoId": repo_id,
                    "ref": git_branch
                },
                "projectSettings": {
                    "framework": proj.get("framework")
                }
            }

            r = vc_api("POST", "/v13/deployments", json=payload)
            if r.status_code not in (200, 201):
                err = r.json().get("error", {}).get("message", r.text[:200])
                return safe_jsonify({"reply": f"❌ Vercel deploy trigger Error: {err}", "action": "error"})

            dep = r.json()
            dep_id = dep.get("id")
            if not dep_id:
                return safe_jsonify({"reply": "❌ Vercel ne deployment ID nahi diya, kuch galat hua.", "action": "error"})

            # Trigger succeeded — now actually wait and check, instead of trusting the
            # immediate response (which is always QUEUED/BUILDING, never finished).
            result = vercel_poll_deployment(dep_id)

            if result["ok"]:
                # state == READY and we have a real, API-confirmed URL.
                return safe_jsonify({
                    "reply": f"✅ Deployment complete!\n**{project_name}**\n🔗 {result['live_url']}\n\nID: `{dep_id}`",
                    "action": "vercel_deploy", "deployment_id": dep_id, "url": result["live_url"], "state": "READY"
                })
            elif result["timed_out"]:
                # Build is still running after our safe polling window — be honest about it,
                # do NOT invent a URL, and tell the user how to check again.
                return safe_jsonify({
                    "reply": (
                        f"⏳ Deploy trigger ho gaya hai (ID: `{dep_id}`), lekin build abhi bhi chal raha hai "
                        f"{25}s ke baad bhi. Vercel builds kabhi kabhi 1-2 min lete hain.\n\n"
                        f"Status check karne ke liye thodi der baad bol: 'check deployment status {dep_id}'."
                    ),
                    "action": "vercel_deploy_pending", "deployment_id": dep_id, "state": result["state"]
                })
            else:
                # Terminal but failed state — ERROR or CANCELED. Report failure honestly.
                error_detail = result["deployment"].get("errorMessage", "") or result["state"]
                return safe_jsonify({
                    "reply": f"❌ Deployment fail ho gaya.\nStatus: **{result['state']}**\n{error_detail}\nID: `{dep_id}`",
                    "action": "error", "deployment_id": dep_id, "state": result["state"]
                })

        except json.JSONDecodeError as e:
            return safe_jsonify({"reply": f"❌ JSON parse error: {str(e)}", "action": "error"})
        except Exception as e:
            return safe_jsonify({"reply": f"❌ Error: {str(e)}", "action": "error"})

    elif cmd == "VERCEL_DEPLOY_STATUS":
        try:
            data = json.loads(value)
            dep_id = data["deployment_id"]
            r = vc_api("GET", f"/v13/deployments/{dep_id}")
            if r.status_code == 200:
                dep = r.json()
                state = dep.get("readyState", "UNKNOWN")
                icon = {"READY": "✅", "ERROR": "❌", "BUILDING": "⏳", "QUEUED": "⏳", "CANCELED": "🚫"}.get(state, "ℹ️")

                if state == "READY":
                    # Only show a URL once the build is actually serving traffic.
                    # Prefer the production alias if Vercel assigned one; fall back to
                    # the unique deployment hostname — both are real values from the API.
                    if dep.get("aliasAssigned") and dep.get("alias"):
                        live_url = f"https://{dep['alias'][0]}"
                    else:
                        live_url = f"https://{dep.get('url', '')}"
                    reply = f"{icon} Deployment `{dep_id}`\nStatus: **{state}**\n🔗 {live_url}"
                elif state == "ERROR":
                    error_detail = dep.get("errorMessage", "")
                    reply = f"{icon} Deployment `{dep_id}`\nStatus: **{state}**\n{error_detail}"
                else:
                    reply = f"{icon} Deployment `{dep_id}`\nStatus: **{state}** — build abhi chal raha hai, URL build complete hone ke baad milega."

                return safe_jsonify({"reply": reply, "action": "vercel_status", "state": state})
            else:
                return safe_jsonify({"reply": f"❌ Status fetch nahi hua: {r.text[:200]}", "action": "error"})
        except json.JSONDecodeError as e:
            return safe_jsonify({"reply": f"❌ JSON parse error: {str(e)}", "action": "error"})
        except Exception as e:
            return safe_jsonify({"reply": f"❌ Error: {str(e)}", "action": "error"})

    elif cmd == "VERCEL_DELETE_PROJECT":
        try:
            data = json.loads(value)
            project_name = data["project_name"]

            # Resolve to the real project first so we report an honest "not found"
            # instead of trusting Vercel to interpret an arbitrary name string.
            proj = vercel_find_project(project_name)
            if not proj:
                return safe_jsonify({
                    "reply": f"❌ Vercel project `{project_name}` nahi mila — pehle hi delete ho chuka ya naam galat hai.",
                    "action": "error"
                })

            proj_id = proj.get("id")
            r = vc_api("DELETE", f"/v9/projects/{proj_id}")
            if r.status_code in (200, 204):
                return safe_jsonify({
                    "reply": f"✅ Vercel project `{project_name}` delete ho gaya.\n\n⚠️ Yeh sirf Vercel se hata hai — GitHub repo abhi bhi waisa hi hai.",
                    "action": "vercel_delete_project", "project_name": project_name
                })
            else:
                err = r.json().get("error", {}).get("message", r.text[:200]) if r.text else r.text[:200]
                return safe_jsonify({"reply": f"❌ Vercel project delete Error: {err}", "action": "error"})
        except json.JSONDecodeError as e:
            return safe_jsonify({"reply": f"❌ JSON parse error: {str(e)}", "action": "error"})
        except Exception as e:
            return safe_jsonify({"reply": f"❌ Error: {str(e)}", "action": "error"})

    # ──────────────────────────────────────────────────────────
    # RENDER
    # ──────────────────────────────────────────────────────────
    elif cmd == "RENDER_LIST_SERVICES":
        r = rd_api("GET", "/services?limit=50")
        if r.status_code == 200:
            items = r.json()
            if not items:
                return safe_jsonify({"reply": "Koi Render service nahi mila.", "action": "render_list", "services": []})
            lines = []
            services = []
            for item in items:
                svc = item.get("service", item)
                name = svc.get("name", "unknown")
                stype = svc.get("type", "service")
                sid = svc.get("id", "")
                url = svc.get("serviceDetails", {}).get("url", "")
                icon = {"web_service": "🌐", "static_site": "📦", "private_service": "🔒",
                        "background_worker": "⚙️", "cron_job": "⏰", "postgres": "🐘", "redis": "🟥"}.get(stype, "🧩")
                line = f"{icon} **{name}** — `{stype}`\nID: `{sid}`"
                if url:
                    line += f"\n🔗 {url}"
                lines.append(line)
                services.append({"name": name, "id": sid, "type": stype})
            return safe_jsonify({
                "reply": f"Tere {len(items)} Render services:\n\n" + "\n\n".join(lines),
                "action": "render_list", "services": services
            })
        else:
            return safe_jsonify({"reply": f"❌ Render services fetch nahi hue: {r.text[:200]}", "action": "error"})

    elif cmd == "RENDER_GET_ENV":
        try:
            data = json.loads(value)
            service_id = data["service_id"]
            r = rd_api("GET", f"/services/{service_id}/env-vars?limit=100")
            if r.status_code == 200:
                items = r.json()
                if not items:
                    return safe_jsonify({"reply": f"Service `{service_id}` me koi env vars nahi hai.", "action": "render_env"})
                lines = [f"`{item['envVar']['key']}` = `{item['envVar']['value']}`" for item in items]
                return safe_jsonify({
                    "reply": f"Env vars for `{service_id}`:\n\n" + "\n".join(lines),
                    "action": "render_env",
                    "env_vars": {item["envVar"]["key"]: item["envVar"]["value"] for item in items}
                })
            else:
                return safe_jsonify({"reply": f"❌ Env vars fetch nahi hue: {r.text[:200]}", "action": "error"})
        except json.JSONDecodeError as e:
            return safe_jsonify({"reply": f"❌ JSON parse error: {str(e)}", "action": "error"})
        except Exception as e:
            return safe_jsonify({"reply": f"❌ Error: {str(e)}", "action": "error"})

    elif cmd == "RENDER_SET_ENV":
        try:
            data = json.loads(value)
            service_id = data["service_id"]
            new_vars = data["env_vars"]

            # Render's PUT replaces the full env var list, so fetch existing first and merge.
            existing_r = rd_api("GET", f"/services/{service_id}/env-vars?limit=100")
            existing = {}
            if existing_r.status_code == 200:
                for item in existing_r.json():
                    existing[item["envVar"]["key"]] = item["envVar"]["value"]

            existing.update(new_vars)
            payload = [{"key": k, "value": v} for k, v in existing.items()]

            r = rd_api("PUT", f"/services/{service_id}/env-vars", json=payload)
            if r.status_code in (200, 201):
                keys = ", ".join(new_vars.keys())
                return safe_jsonify({
                    "reply": f"✅ Env vars update ho gaye for `{service_id}`!\nUpdated keys: `{keys}`\n\n⚠️ Service redeploy hoga automatically Render ki taraf se.",
                    "action": "render_env_update"
                })
            else:
                return safe_jsonify({"reply": f"❌ Env update Error: {r.text[:200]}", "action": "error"})
        except json.JSONDecodeError as e:
            return safe_jsonify({"reply": f"❌ JSON parse error: {str(e)}", "action": "error"})
        except Exception as e:
            return safe_jsonify({"reply": f"❌ Error: {str(e)}", "action": "error"})

    elif cmd == "RENDER_DEPLOY":
        try:
            data = json.loads(value)
            service_id = data["service_id"]
            clear_cache = data.get("clear_cache", False)

            payload = {"clearCache": "clear" if clear_cache else "do_not_clear"}
            r = rd_api("POST", f"/services/{service_id}/deploys", json=payload)
            if r.status_code in (200, 201):
                dep = r.json()
                dep_id = dep.get("id", "")
                status = dep.get("status", "queued")
                cache_note = "(cache cleared)" if clear_cache else ""
                return safe_jsonify({
                    "reply": f"🚀 Deploy trigger ho gaya for `{service_id}` {cache_note}\nDeploy ID: `{dep_id}`\nStatus: **{status}**",
                    "action": "render_deploy", "deploy_id": dep_id, "status": status
                })
            else:
                return safe_jsonify({"reply": f"❌ Render deploy Error: {r.text[:200]}", "action": "error"})
        except json.JSONDecodeError as e:
            return safe_jsonify({"reply": f"❌ JSON parse error: {str(e)}", "action": "error"})
        except Exception as e:
            return safe_jsonify({"reply": f"❌ Error: {str(e)}", "action": "error"})

    # ──────────────────────────────────────────────────────────
    # PLAIN AI RESPONSE
    # ──────────────────────────────────────────────────────────
    else:
        if looks_fabricated(ai_text):
            return safe_jsonify({
                "reply": "⚠️ Mujhe ek real command run karna chahiye tha is request ke liye, "
                         "lekin maine galti se ek fake-looking response generate kar diya tha jo block ho gaya. "
                         "Dobara try kar — agar specific repo/project/service ka naam bata de to main sahi command chalaunga.",
                "action": "warning"
            })
        return safe_jsonify({"reply": ai_text, "action": "message"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
