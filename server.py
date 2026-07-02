from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import requests
import os
import base64
import json
import re
import time
import hashlib
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
# ════════════════════════════════════════════════════════════════
_REAL_SECRETS = [s for s in [GITHUB_TOKEN, OPENROUTER_KEY, VERCEL_TOKEN, RENDER_TOKEN] if s]

_SECRET_PATTERNS = [
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"sk-or-v1-[A-Za-z0-9]{20,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"Bearer\s+[A-Za-z0-9\-_\.]{15,}", re.I),
    re.compile(r"rnd_[A-Za-z0-9]{20,}"),
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


# ════════════════════════════════════════════════════════════════
#  GITHUB / VERCEL / RENDER HTTP HELPERS
# ════════════════════════════════════════════════════════════════
def gh_api(method, endpoint, **kwargs):
    url = f"https://api.github.com{endpoint}"
    return requests.request(method, url, headers=GH_HEADERS, timeout=20, **kwargs)


def get_file_sha(repo, path):
    r = gh_api("GET", f"/repos/{GITHUB_USERNAME}/{repo}/contents/{path}")
    if r.status_code == 200:
        return r.json().get("sha")
    return None


def vc_api(method, endpoint, **kwargs):
    url = f"https://api.vercel.com{endpoint}"
    return requests.request(method, url, headers=VERCEL_HEADERS, timeout=20, **kwargs)


def vercel_find_project(name):
    r = vc_api("GET", "/v9/projects")
    if r.status_code != 200:
        return None
    for p in r.json().get("projects", []):
        if p.get("name") == name:
            return p
    return None


VERCEL_TERMINAL_STATES = {"READY", "ERROR", "CANCELED"}


def vercel_poll_deployment(deployment_id, max_wait_seconds=25, interval_seconds=3):
    """Poll GET /v13/deployments/{id} until terminal readyState or timeout.
    Short timeout because this runs synchronously inside one Flask request."""
    elapsed = 0
    last_dep = {}
    while elapsed <= max_wait_seconds:
        r = vc_api("GET", f"/v13/deployments/{deployment_id}")
        if r.status_code != 200:
            time.sleep(interval_seconds)
            elapsed += interval_seconds
            continue

        dep = r.json()
        last_dep = dep
        state = dep.get("readyState", "UNKNOWN")

        if state in VERCEL_TERMINAL_STATES:
            live_url = None
            if state == "READY":
                raw_url = dep.get("url")
                if raw_url:
                    live_url = f"https://{raw_url}"
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

    return {
        "ok": False,
        "timed_out": True,
        "deployment": last_dep,
        "state": last_dep.get("readyState", "UNKNOWN"),
        "live_url": None,
    }


def rd_api(method, endpoint, **kwargs):
    url = f"https://api.render.com/v1{endpoint}"
    return requests.request(method, url, headers=RENDER_HEADERS, timeout=20, **kwargs)


# ════════════════════════════════════════════════════════════════
#  DESTRUCTIVE-ACTION CONFIRMATION
# ════════════════════════════════════════════════════════════════
DESTRUCTIVE_COMMANDS = {
    "DELETE_REPO", "DELETE_FILE", "VERCEL_DELETE_PROJECT",
    "DELETE_BRANCH", "RENDER_DELETE_SERVICE", "RENDER_SUSPEND_SERVICE",
}


def confirm_token(cmd, value):
    """Deterministic token binding a specific (command, value) pair, so a client
    can only 'confirm' the exact destructive action that was actually proposed."""
    raw = f"{cmd}:{value or ''}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def build_confirmation(cmd, params):
    """Build the confirm_required response for a destructive command, given its
    resolved params dict. `value` (what gets hashed into the token and replayed
    back by the frontend) is the JSON-serialized params dict for consistency."""
    value = json.dumps(params, sort_keys=True)
    token = confirm_token(cmd, value)

    if cmd == "DELETE_REPO":
        target_desc = f"GitHub repo `{params.get('repo')}`"
        warn_text = "Ye permanently delete ho jayega — saara code, history, sab kuch. Wapas nahi aayega."
    elif cmd == "DELETE_FILE":
        target_desc = f"`{params.get('path')}` in repo `{params.get('repo')}`"
        warn_text = "Ye file repo se permanently hat jayegi."
    elif cmd == "VERCEL_DELETE_PROJECT":
        target_desc = f"Vercel project `{params.get('project_name')}`"
        warn_text = "Vercel project aur uski saari deployments delete ho jayengi (GitHub repo safe rahega)."
    elif cmd == "DELETE_BRANCH":
        target_desc = f"Branch `{params.get('branch')}` in repo `{params.get('repo')}`"
        warn_text = "Branch aur uska commit history reference permanently hat jayega."
    elif cmd == "RENDER_DELETE_SERVICE":
        target_desc = f"Render service `{params.get('service_id')}`"
        warn_text = "Service permanently delete ho jayegi — logs, deploy history, sab kuch. Wapas nahi aayega."
    elif cmd == "RENDER_SUSPEND_SERVICE":
        target_desc = f"Render service `{params.get('service_id')}`"
        warn_text = "Service suspend ho jayegi aur live traffic serve nahi karegi jab tak resume na karo."
    else:
        target_desc = str(params)
        warn_text = "Ye action wapas nahi ho sakta."

    return {
        "reply": f"⚠️ **Pakka?**\n\n{target_desc} delete karne wala hu.\n\n{warn_text}",
        "action": "confirm_required",
        "pending_command": cmd,
        "pending_value": value,
        "confirm_token": token,
        "source": "direct",
    }


# ════════════════════════════════════════════════════════════════
#  execute_command — THE SINGLE SHARED EXECUTOR
#  Called by BOTH the regex/direct path and the AI command path.
#  Takes a command name + a params dict (already validated/parsed),
#  always returns a plain dict (not a Flask response) so callers can
#  attach "source" before jsonifying.
# ════════════════════════════════════════════════════════════════
def execute_command(cmd, params):
    params = params or {}

    try:
        # ──────────────── GITHUB ────────────────
        if cmd == "CREATE_REPO":
            repo_name = re.sub(r"[^a-zA-Z0-9_.-]", "-", params["repo"].strip())
            r = gh_api("POST", "/user/repos", json={"name": repo_name, "private": False, "auto_init": True})
            if r.status_code == 201:
                data = r.json()
                return {"reply": f"✅ Repo ban gaya!\n**{repo_name}**\n🔗 {data['html_url']}",
                        "action": "create_repo", "url": data["html_url"], "repo": repo_name}
            elif r.status_code == 422:
                return {"reply": f"⚠️ Repo `{repo_name}` already exist karta hai.", "action": "warning"}
            else:
                return {"reply": f"❌ GitHub Error: {r.json().get('message', 'Repo nahi bana')}", "action": "error"}

        elif cmd == "DELETE_REPO":
            repo_name = params["repo"].strip()
            r = gh_api("DELETE", f"/repos/{GITHUB_USERNAME}/{repo_name}")
            if r.status_code == 204:
                return {"reply": f"🗑️ Repo `{repo_name}` delete ho gaya.", "action": "delete_repo"}
            else:
                msg = r.json().get("message", "Repo delete nahi hua") if r.content else "Repo delete nahi hua"
                return {"reply": f"❌ Delete Error: {msg}", "action": "error"}

        elif cmd == "LIST_REPOS":
            r = gh_api("GET", f"/users/{GITHUB_USERNAME}/repos?per_page=20&sort=updated")
            if r.status_code == 200:
                repos = r.json()
                if not repos:
                    return {"reply": "Koi repo nahi hai abhi.", "action": "list_repos", "repos": []}
                lines = [f"📁 **{rp['name']}** — ⭐{rp['stargazers_count']} — `{rp['visibility']}`\n🔗 {rp['html_url']}" for rp in repos]
                return {"reply": f"Tere {len(repos)} repos:\n\n" + "\n\n".join(lines), "action": "list_repos",
                        "repos": [{"name": rp["name"], "url": rp["html_url"]} for rp in repos]}
            else:
                return {"reply": "❌ Repos fetch nahi hue.", "action": "error"}

        elif cmd == "LIST_FILES":
            repo = params["repo"]
            path = params.get("path", "").strip("/")
            endpoint = f"/repos/{GITHUB_USERNAME}/{repo}/contents/{path}" if path else f"/repos/{GITHUB_USERNAME}/{repo}/contents"
            r = gh_api("GET", endpoint)
            if r.status_code == 200:
                items = r.json()
                if not isinstance(items, list):
                    items = [items]
                lines = [f"{'📁' if item['type'] == 'dir' else '📄'} {item['path']}" for item in items]
                reply = f"Files in `{repo}/{path or ''}`:\n\n" + "\n".join(lines)
                return {"reply": reply, "action": "list_files"}
            else:
                return {"reply": f"❌ Files fetch nahi hue: {r.json().get('message','')}", "action": "error"}

        elif cmd == "READ_FILE":
            repo, path = params["repo"], params["path"]
            r = gh_api("GET", f"/repos/{GITHUB_USERNAME}/{repo}/contents/{path}")
            if r.status_code == 200:
                file_data = r.json()
                content = base64.b64decode(file_data["content"]).decode("utf-8", errors="replace")
                preview = content[:2000] + ("\n...[truncated]" if len(content) > 2000 else "")
                return {"reply": f"📄 `{path}` ({file_data['size']} bytes):\n\n```\n{preview}\n```",
                        "action": "read_file", "content": content, "sha": file_data["sha"]}
            else:
                return {"reply": f"❌ File nahi mili: {r.json().get('message','')}", "action": "error"}

        elif cmd == "CREATE_FILE":
            repo, path, content = params["repo"], params["path"], params["content"]
            message = params.get("message", f"Add {path} via DevOps Agent")
            content_b64 = base64.b64encode(content.encode()).decode()
            existing_sha = get_file_sha(repo, path)
            payload = {"message": message, "content": content_b64}
            if existing_sha:
                payload["sha"] = existing_sha
            r = gh_api("PUT", f"/repos/{GITHUB_USERNAME}/{repo}/contents/{path}", json=payload)
            if r.status_code in (200, 201):
                url = r.json()["content"]["html_url"]
                action = "update_file" if existing_sha else "create_file"
                verb = "Update" if existing_sha else "Bana"
                return {"reply": f"✅ File {verb} di!\n**{path}**\n🔗 {url}", "action": action, "url": url, "repo": repo}
            else:
                return {"reply": f"❌ GitHub Error: {r.json().get('message','File nahi bani')}", "action": "error"}

        elif cmd == "EDIT_FILE":
            repo, path, content = params["repo"], params["path"], params["content"]
            message = params.get("message", f"Update {path} via DevOps Agent")
            sha = get_file_sha(repo, path)
            if not sha:
                return {"reply": f"❌ File `{path}` exist nahi karti repo `{repo}` me.", "action": "error"}
            content_b64 = base64.b64encode(content.encode()).decode()
            r = gh_api("PUT", f"/repos/{GITHUB_USERNAME}/{repo}/contents/{path}",
                       json={"message": message, "content": content_b64, "sha": sha})
            if r.status_code in (200, 201):
                url = r.json()["content"]["html_url"]
                return {"reply": f"✅ File update ho gayi!\n**{path}**\n🔗 {url}", "action": "update_file", "url": url, "repo": repo}
            else:
                return {"reply": f"❌ Update Error: {r.json().get('message','')}", "action": "error"}

        elif cmd == "DELETE_FILE":
            repo, path = params["repo"], params["path"]
            message = params.get("message", f"Delete {path} via DevOps Agent")
            sha = get_file_sha(repo, path)
            if not sha:
                return {"reply": f"❌ File `{path}` exist nahi karti.", "action": "error"}
            r = gh_api("DELETE", f"/repos/{GITHUB_USERNAME}/{repo}/contents/{path}",
                       json={"message": message, "sha": sha})
            if r.status_code == 200:
                return {"reply": f"🗑️ File `{path}` delete ho gayi.", "action": "delete_file"}
            else:
                return {"reply": f"❌ Delete Error: {r.json().get('message','')}", "action": "error"}

        elif cmd == "CREATE_BRANCH":
            repo = params["repo"]
            branch = params["branch"]
            base = params.get("base", "main")
            base_ref = gh_api("GET", f"/repos/{GITHUB_USERNAME}/{repo}/git/ref/heads/{base}")
            if base_ref.status_code != 200:
                return {"reply": f"❌ Base branch `{base}` nahi mila repo `{repo}` me.", "action": "error"}
            base_sha = base_ref.json()["object"]["sha"]
            r = gh_api("POST", f"/repos/{GITHUB_USERNAME}/{repo}/git/refs",
                       json={"ref": f"refs/heads/{branch}", "sha": base_sha})
            if r.status_code == 201:
                return {"reply": f"✅ Branch `{branch}` ban gaya repo `{repo}` me (from `{base}`).",
                        "action": "create_branch", "repo": repo, "branch": branch}
            elif r.status_code == 422:
                return {"reply": f"⚠️ Branch `{branch}` already exist karta hai.", "action": "warning"}
            else:
                return {"reply": f"❌ Branch create Error: {r.json().get('message','')}", "action": "error"}

        elif cmd == "DELETE_BRANCH":
            repo, branch = params["repo"], params["branch"]
            r = gh_api("DELETE", f"/repos/{GITHUB_USERNAME}/{repo}/git/refs/heads/{branch}")
            if r.status_code == 204:
                return {"reply": f"🗑️ Branch `{branch}` delete ho gaya repo `{repo}` se.", "action": "delete_branch"}
            else:
                msg = r.json().get("message", "") if r.content else ""
                return {"reply": f"❌ Branch delete Error: {msg}", "action": "error"}

        elif cmd == "CREATE_PR":
            repo = params["repo"]
            head = params["head"]
            base = params.get("base", "main")
            title = params.get("title", f"Merge {head} into {base}")
            body = params.get("body", "")
            r = gh_api("POST", f"/repos/{GITHUB_USERNAME}/{repo}/pulls",
                       json={"title": title, "head": head, "base": base, "body": body})
            if r.status_code == 201:
                pr = r.json()
                return {"reply": f"✅ PR ban gaya!\n**#{pr['number']} — {title}**\n{head} → {base}\n🔗 {pr['html_url']}",
                        "action": "create_pr", "url": pr["html_url"], "pr_number": pr["number"]}
            else:
                return {"reply": f"❌ PR create Error: {r.json().get('message','')}", "action": "error"}

        elif cmd == "MERGE_PR":
            repo = params["repo"]
            pr_number = params["pr_number"]
            method = params.get("merge_method", "merge")
            r = gh_api("PUT", f"/repos/{GITHUB_USERNAME}/{repo}/pulls/{pr_number}/merge",
                       json={"merge_method": method})
            if r.status_code == 200:
                return {"reply": f"✅ PR #{pr_number} merge ho gaya repo `{repo}` me (`{method}`).",
                        "action": "merge_pr", "pr_number": pr_number}
            else:
                return {"reply": f"❌ Merge Error: {r.json().get('message','PR merge nahi hua — conflicts ho sakte hain')}", "action": "error"}

        elif cmd == "LIST_COMMITS":
            repo = params["repo"]
            branch = params.get("branch", "")
            limit = params.get("limit", 10)
            endpoint = f"/repos/{GITHUB_USERNAME}/{repo}/commits?per_page={limit}"
            if branch:
                endpoint += f"&sha={branch}"
            r = gh_api("GET", endpoint)
            if r.status_code == 200:
                commits = r.json()
                if not commits:
                    return {"reply": "Koi commits nahi mile.", "action": "list_commits", "commits": []}
                lines = []
                for c in commits:
                    sha_short = c["sha"][:7]
                    msg = c["commit"]["message"].split("\n")[0][:80]
                    author = c["commit"]["author"]["name"]
                    lines.append(f"`{sha_short}` {msg} — _{author}_")
                return {"reply": f"Recent {len(commits)} commits in `{repo}`:\n\n" + "\n".join(lines),
                        "action": "list_commits"}
            else:
                return {"reply": f"❌ Commits fetch nahi hue: {r.json().get('message','')}", "action": "error"}

        elif cmd == "CREATE_ISSUE":
            repo = params["repo"]
            title = params["title"]
            body = params.get("body", "")
            r = gh_api("POST", f"/repos/{GITHUB_USERNAME}/{repo}/issues", json={"title": title, "body": body})
            if r.status_code == 201:
                issue = r.json()
                return {"reply": f"✅ Issue ban gaya!\n**#{issue['number']} — {title}**\n🔗 {issue['html_url']}",
                        "action": "create_issue", "url": issue["html_url"], "issue_number": issue["number"]}
            else:
                return {"reply": f"❌ Issue create Error: {r.json().get('message','')}", "action": "error"}

        elif cmd == "GET_REPO_INFO":
            repo = params["repo"]
            r = gh_api("GET", f"/repos/{GITHUB_USERNAME}/{repo}")
            if r.status_code == 200:
                d = r.json()
                reply = (f"📁 **{d['name']}**\n"
                         f"⭐ Stars: {d['stargazers_count']} | 🍴 Forks: {d['forks_count']} | "
                         f"👁️ Watchers: {d['watchers_count']}\n"
                         f"🔓 Visibility: `{d['visibility']}`\n"
                         f"🕓 Last updated: {d['updated_at']}\n"
                         f"🔗 {d['html_url']}")
                if d.get("description"):
                    reply += f"\n📝 {d['description']}"
                return {"reply": reply, "action": "repo_info"}
            else:
                return {"reply": f"❌ Repo info fetch nahi hui: {r.json().get('message','')}", "action": "error"}

        elif cmd == "RENAME_REPO":
            repo = params["repo"]
            new_name = re.sub(r"[^a-zA-Z0-9_.-]", "-", params["new_name"].strip())
            r = gh_api("PATCH", f"/repos/{GITHUB_USERNAME}/{repo}", json={"name": new_name})
            if r.status_code == 200:
                d = r.json()
                return {"reply": f"✅ Repo rename ho gaya!\n`{repo}` → **{new_name}**\n🔗 {d['html_url']}",
                        "action": "rename_repo", "url": d["html_url"]}
            else:
                return {"reply": f"❌ Rename Error: {r.json().get('message','')}", "action": "error"}

        elif cmd == "TOGGLE_REPO_VISIBILITY":
            repo = params["repo"]
            private = params["private"]
            r = gh_api("PATCH", f"/repos/{GITHUB_USERNAME}/{repo}", json={"private": private})
            if r.status_code == 200:
                vis = "private 🔒" if private else "public 🌐"
                return {"reply": f"✅ Repo `{repo}` ab **{vis}** hai.", "action": "toggle_visibility"}
            else:
                return {"reply": f"❌ Visibility change Error: {r.json().get('message','')}", "action": "error"}

        elif cmd == "ADD_COLLABORATOR":
            repo = params["repo"]
            username = params["username"]
            permission = params.get("permission", "push")
            r = gh_api("PUT", f"/repos/{GITHUB_USERNAME}/{repo}/collaborators/{username}",
                       json={"permission": permission})
            if r.status_code in (201, 204):
                note = "Invite bhej diya gaya" if r.status_code == 201 else "Already collaborator tha, permission update ho gayi"
                return {"reply": f"✅ `{username}` ko `{repo}` pe `{permission}` access mil gaya.\n{note}.",
                        "action": "add_collaborator"}
            else:
                return {"reply": f"❌ Collaborator add Error: {r.json().get('message','')}", "action": "error"}

        # ──────────────── VERCEL ────────────────
        elif cmd == "VERCEL_LIST_PROJECTS":
            r = vc_api("GET", "/v9/projects")
            if r.status_code == 200:
                projects = r.json().get("projects", [])
                if not projects:
                    return {"reply": "Koi Vercel project nahi mila.", "action": "vercel_list", "projects": []}
                lines = []
                for p in projects:
                    live = f"https://{p['name']}.vercel.app"
                    lines.append(f"▲ **{p['name']}** — `{p.get('framework') or 'static'}`\n🔗 {live}")
                return {"reply": f"Tere {len(projects)} Vercel projects:\n\n" + "\n\n".join(lines),
                        "action": "vercel_list", "projects": [{"name": p["name"], "id": p["id"]} for p in projects]}
            else:
                return {"reply": f"❌ Vercel projects fetch nahi hue: {r.text[:200]}", "action": "error"}

        elif cmd == "VERCEL_IMPORT_REPO":
            repo = params["repo"]
            project_name = params.get("project_name") or repo
            framework = params.get("framework")

            payload = {
                "name": project_name,
                "gitRepository": {"type": "github", "repo": f"{GITHUB_USERNAME}/{repo}"},
                "framework": framework if framework else None
            }

            r = vc_api("POST", "/v11/projects", json=payload)
            if r.status_code in (200, 201):
                proj = r.json()
                latest = proj.get("latestDeployments") or []
                dep_id = (latest[0].get("uid") or latest[0].get("id")) if latest else None

                reply = (f"✅ `{repo}` Vercel se connect ho gaya!\n**Project: {proj['name']}**\n"
                         f"Project ID: `{proj.get('id')}`\n\n")
                if dep_id:
                    reply += (f"⏳ Vercel ne automatically ek initial build queue kar diya hai (Deployment ID: `{dep_id}`).\n"
                              f"Status check karne ke liye bol: 'check deployment status {dep_id}' — "
                              f"tabhi main real live URL bata sakta hoon, build complete hone ke baad.")
                else:
                    reply += f"Build abhi queue nahi hua. Deploy trigger karne ke liye bol: 'deploy {proj['name']} to vercel'."

                return {"reply": reply, "action": "vercel_import", "project_name": proj["name"],
                        "project_id": proj.get("id"), "deployment_id": dep_id}
            else:
                err = r.json().get("error", {}).get("message", r.text[:200])
                return {"reply": f"❌ Vercel import Error: {err}", "action": "error"}

        elif cmd == "VERCEL_DEPLOY":
            project_name = params["project_name"]
            proj = vercel_find_project(project_name)
            if not proj:
                return {"reply": f"❌ Vercel project `{project_name}` nahi mila. Pehle import kar.", "action": "error"}

            git_repo = proj.get("link", {})
            repo_id = git_repo.get("repoId")
            git_branch = git_repo.get("productionBranch", "main")

            if not repo_id:
                return {"reply": f"❌ Project `{project_name}` GitHub se linked nahi hai (no repoId). Pehle import kar.",
                        "action": "error"}

            payload = {
                "name": project_name,
                "target": "production",
                "gitSource": {"type": "github", "repoId": repo_id, "ref": git_branch},
                "projectSettings": {"framework": proj.get("framework")}
            }

            r = vc_api("POST", "/v13/deployments", json=payload)
            if r.status_code not in (200, 201):
                err = r.json().get("error", {}).get("message", r.text[:200])
                return {"reply": f"❌ Vercel deploy trigger Error: {err}", "action": "error"}

            dep = r.json()
            dep_id = dep.get("id")
            if not dep_id:
                return {"reply": "❌ Vercel ne deployment ID nahi diya, kuch galat hua.", "action": "error"}

            result = vercel_poll_deployment(dep_id)

            if result["ok"]:
                return {"reply": f"✅ Deployment complete!\n**{project_name}**\n🔗 {result['live_url']}\n\nID: `{dep_id}`",
                        "action": "vercel_deploy", "deployment_id": dep_id, "url": result["live_url"], "state": "READY"}
            elif result["timed_out"]:
                return {"reply": (f"⏳ Deploy trigger ho gaya hai (ID: `{dep_id}`), lekin build abhi bhi chal raha hai "
                                   f"25s ke baad bhi. Vercel builds kabhi kabhi 1-2 min lete hain.\n\n"
                                   f"Status check karne ke liye thodi der baad bol: 'check deployment status {dep_id}'."),
                        "action": "vercel_deploy_pending", "deployment_id": dep_id, "state": result["state"]}
            else:
                error_detail = result["deployment"].get("errorMessage", "") or result["state"]
                return {"reply": f"❌ Deployment fail ho gaya.\nStatus: **{result['state']}**\n{error_detail}\nID: `{dep_id}`",
                        "action": "error", "deployment_id": dep_id, "state": result["state"]}

        elif cmd == "VERCEL_DEPLOY_STATUS":
            dep_id = params["deployment_id"]
            r = vc_api("GET", f"/v13/deployments/{dep_id}")
            if r.status_code == 200:
                dep = r.json()
                state = dep.get("readyState", "UNKNOWN")
                icon = {"READY": "✅", "ERROR": "❌", "BUILDING": "⏳", "QUEUED": "⏳", "CANCELED": "🚫"}.get(state, "ℹ️")

                if state == "READY":
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

                return {"reply": reply, "action": "vercel_status", "state": state}
            else:
                return {"reply": f"❌ Status fetch nahi hua: {r.text[:200]}", "action": "error"}

        elif cmd == "VERCEL_DELETE_PROJECT":
            project_name = params["project_name"]
            proj = vercel_find_project(project_name)
            if not proj:
                return {"reply": f"❌ Vercel project `{project_name}` nahi mila — pehle hi delete ho chuka ya naam galat hai.",
                        "action": "error"}
            proj_id = proj.get("id")
            r = vc_api("DELETE", f"/v9/projects/{proj_id}")
            if r.status_code in (200, 204):
                return {"reply": f"✅ Vercel project `{project_name}` delete ho gaya.\n\n⚠️ Yeh sirf Vercel se hata hai — GitHub repo abhi bhi waisa hi hai.",
                        "action": "vercel_delete_project", "project_name": project_name}
            else:
                err = r.json().get("error", {}).get("message", r.text[:200]) if r.text else r.text[:200]
                return {"reply": f"❌ Vercel project delete Error: {err}", "action": "error"}

        elif cmd == "VERCEL_GET_ENV":
            project_name = params["project_name"]
            proj = vercel_find_project(project_name)
            if not proj:
                return {"reply": f"❌ Vercel project `{project_name}` nahi mila.", "action": "error"}
            proj_id = proj.get("id")
            r = vc_api("GET", f"/v9/projects/{proj_id}/env")
            if r.status_code == 200:
                envs = r.json().get("envs", [])
                if not envs:
                    return {"reply": f"Project `{project_name}` me koi env vars nahi hai.", "action": "vercel_env"}
                lines = [f"`{e['key']}` — targets: {', '.join(e.get('target', []))}" for e in envs]
                return {"reply": f"Env vars for `{project_name}` (values encrypted, sirf keys dikha sakta hu):\n\n" + "\n".join(lines),
                        "action": "vercel_env"}
            else:
                return {"reply": f"❌ Env vars fetch nahi hue: {r.text[:200]}", "action": "error"}

        elif cmd == "VERCEL_SET_ENV":
            project_name = params["project_name"]
            key = params["key"]
            value = params["value"]
            target = params.get("target", ["production", "preview", "development"])
            proj = vercel_find_project(project_name)
            if not proj:
                return {"reply": f"❌ Vercel project `{project_name}` nahi mila.", "action": "error"}
            proj_id = proj.get("id")
            r = vc_api("POST", f"/v10/projects/{proj_id}/env",
                       json={"key": key, "value": value, "type": "encrypted", "target": target})
            if r.status_code in (200, 201):
                return {"reply": f"✅ Env var `{key}` set ho gaya `{project_name}` me.\n⚠️ Naya deploy trigger karo change apply karne ke liye.",
                        "action": "vercel_env_set"}
            else:
                err = r.json().get("error", {}).get("message", r.text[:200])
                return {"reply": f"❌ Env set Error: {err}", "action": "error"}

        elif cmd == "VERCEL_ADD_DOMAIN":
            project_name = params["project_name"]
            domain = params["domain"]
            proj = vercel_find_project(project_name)
            if not proj:
                return {"reply": f"❌ Vercel project `{project_name}` nahi mila.", "action": "error"}
            proj_id = proj.get("id")
            r = vc_api("POST", f"/v10/projects/{proj_id}/domains", json={"name": domain})
            if r.status_code in (200, 201):
                return {"reply": f"✅ Domain `{domain}` add ho gaya `{project_name}` pe.\n⚠️ DNS records apne domain provider pe configure karne padenge — Vercel dashboard me instructions milenge.",
                        "action": "vercel_add_domain"}
            else:
                err = r.json().get("error", {}).get("message", r.text[:200])
                return {"reply": f"❌ Domain add Error: {err}", "action": "error"}

        elif cmd == "VERCEL_LIST_DEPLOYMENTS":
            project_name = params["project_name"]
            limit = params.get("limit", 10)
            proj = vercel_find_project(project_name)
            if not proj:
                return {"reply": f"❌ Vercel project `{project_name}` nahi mila.", "action": "error"}
            proj_id = proj.get("id")
            r = vc_api("GET", f"/v6/deployments?projectId={proj_id}&limit={limit}")
            if r.status_code == 200:
                deps = r.json().get("deployments", [])
                if not deps:
                    return {"reply": "Koi deployments nahi mile.", "action": "vercel_deployments"}
                icon_map = {"READY": "✅", "ERROR": "❌", "BUILDING": "⏳", "QUEUED": "⏳", "CANCELED": "🚫"}
                lines = []
                for d in deps:
                    icon = icon_map.get(d.get("state", ""), "ℹ️")
                    lines.append(f"{icon} `{d['uid']}` — {d.get('state')} — {d.get('target', 'preview')}")
                return {"reply": f"Recent {len(deps)} deployments for `{project_name}`:\n\n" + "\n".join(lines),
                        "action": "vercel_deployments"}
            else:
                return {"reply": f"❌ Deployments fetch nahi hue: {r.text[:200]}", "action": "error"}

        elif cmd == "VERCEL_ROLLBACK":
            deployment_id = params["deployment_id"]
            r = vc_api("GET", f"/v13/deployments/{deployment_id}")
            if r.status_code != 200:
                return {"reply": f"❌ Deployment `{deployment_id}` nahi mila.", "action": "error"}
            dep = r.json()
            proj_id = dep.get("projectId")
            r3 = vc_api("POST", f"/v9/projects/{proj_id}/promote/{deployment_id}")
            if r3.status_code in (200, 201, 204):
                return {"reply": f"✅ Rollback ho gaya — deployment `{deployment_id}` ab production pe promote ho gaya.",
                        "action": "vercel_rollback"}
            else:
                err = r3.text[:200]
                return {"reply": f"❌ Rollback Error: {err}\n\nNote: Vercel rollback API access-level pe restricted ho sakta hai plan ke hisaab se.",
                        "action": "error"}

        elif cmd == "VERCEL_GET_LOGS":
            deployment_id = params["deployment_id"]
            limit = params.get("limit", 50)
            r = vc_api("GET", f"/v2/deployments/{deployment_id}/events?limit={limit}")
            if r.status_code == 200:
                events = r.json()
                if not events:
                    return {"reply": f"Deployment `{deployment_id}` ke liye koi logs nahi mile.", "action": "vercel_logs"}
                lines = []
                for e in events[-limit:]:
                    text = e.get("payload", {}).get("text") or e.get("text") or ""
                    if text:
                        lines.append(text.strip())
                preview = "\n".join(lines[-40:]) or "(logs khaali hain)"
                return {"reply": f"📜 Logs for `{deployment_id}` (last {len(lines[-40:])} lines):\n\n```\n{preview}\n```",
                        "action": "vercel_logs"}
            else:
                return {"reply": f"❌ Logs fetch nahi hue: {r.text[:200]}", "action": "error"}

        # ──────────────── RENDER ────────────────
        elif cmd == "RENDER_LIST_SERVICES":
            r = rd_api("GET", "/services?limit=50")
            if r.status_code == 200:
                items = r.json()
                if not items:
                    return {"reply": "Koi Render service nahi mila.", "action": "render_list", "services": []}
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
                return {"reply": f"Tere {len(items)} Render services:\n\n" + "\n\n".join(lines),
                        "action": "render_list", "services": services}
            else:
                return {"reply": f"❌ Render services fetch nahi hue: {r.text[:200]}", "action": "error"}

        elif cmd == "RENDER_GET_ENV":
            service_id = params["service_id"]
            r = rd_api("GET", f"/services/{service_id}/env-vars?limit=100")
            if r.status_code == 200:
                items = r.json()
                if not items:
                    return {"reply": f"Service `{service_id}` me koi env vars nahi hai.", "action": "render_env"}
                lines = [f"`{item['envVar']['key']}` = `{item['envVar']['value']}`" for item in items]
                return {"reply": f"Env vars for `{service_id}`:\n\n" + "\n".join(lines), "action": "render_env",
                        "env_vars": {item["envVar"]["key"]: item["envVar"]["value"] for item in items}}
            else:
                return {"reply": f"❌ Env vars fetch nahi hue: {r.text[:200]}", "action": "error"}

        elif cmd == "RENDER_SET_ENV":
            service_id = params["service_id"]
            new_vars = params["env_vars"]

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
                return {"reply": f"✅ Env vars update ho gaye for `{service_id}`!\nUpdated keys: `{keys}`\n\n⚠️ Service redeploy hoga automatically Render ki taraf se.",
                        "action": "render_env_update"}
            else:
                return {"reply": f"❌ Env update Error: {r.text[:200]}", "action": "error"}

        elif cmd == "RENDER_DEPLOY":
            service_id = params["service_id"]
            clear_cache = params.get("clear_cache", False)
            payload = {"clearCache": "clear" if clear_cache else "do_not_clear"}
            r = rd_api("POST", f"/services/{service_id}/deploys", json=payload)
            if r.status_code in (200, 201):
                dep = r.json()
                dep_id = dep.get("id", "")
                status = dep.get("status", "queued")
                cache_note = "(cache cleared)" if clear_cache else ""
                return {"reply": f"🚀 Deploy trigger ho gaya for `{service_id}` {cache_note}\nDeploy ID: `{dep_id}`\nStatus: **{status}**",
                        "action": "render_deploy", "deploy_id": dep_id, "status": status}
            else:
                return {"reply": f"❌ Render deploy Error: {r.text[:200]}", "action": "error"}

        elif cmd == "RENDER_DELETE_SERVICE":
            service_id = params["service_id"]
            r = rd_api("DELETE", f"/services/{service_id}")
            if r.status_code in (200, 204):
                return {"reply": f"🗑️ Render service `{service_id}` delete ho gaya.", "action": "render_delete_service"}
            else:
                return {"reply": f"❌ Service delete Error: {r.text[:200]}", "action": "error"}

        elif cmd == "RENDER_CREATE_SERVICE":
            repo = params["repo"]
            name = params.get("name", repo)
            svc_type = params.get("type", "web_service")
            env = params.get("env", "node")
            plan = params.get("plan", "free")
            branch = params.get("branch", "main")
            build_cmd = params.get("build_command", "")
            start_cmd = params.get("start_command", "")
            payload = {
                "type": svc_type,
                "name": name,
                "repo": f"https://github.com/{GITHUB_USERNAME}/{repo}",
                "branch": branch,
                "serviceDetails": {
                    "env": env,
                    "plan": plan,
                    "envSpecificDetails": {"buildCommand": build_cmd, "startCommand": start_cmd},
                },
            }
            r = rd_api("POST", "/services", json=payload)
            if r.status_code in (200, 201):
                d = r.json()
                svc = d.get("service", d)
                url = svc.get("serviceDetails", {}).get("url", "")
                reply = f"✅ Render service ban gaya!\n**{svc.get('name')}**\nID: `{svc.get('id')}`"
                if url:
                    reply += f"\n🔗 {url}"
                return {"reply": reply, "action": "render_create_service", "service_id": svc.get("id")}
            else:
                return {"reply": f"❌ Service create Error: {r.text[:200]}", "action": "error"}

        elif cmd == "RENDER_GET_LOGS":
            service_id = params["service_id"]
            limit = params.get("limit", 50)
            r = rd_api("GET", f"/logs?ownerId=&resource={service_id}&limit={limit}")
            if r.status_code != 200:
                # fallback: some Render accounts require the /log-stream style query params
                r = rd_api("GET", f"/services/{service_id}/logs?limit={limit}")
            if r.status_code == 200:
                data = r.json()
                items = data.get("logs", data) if isinstance(data, dict) else data
                if not items:
                    return {"reply": f"Service `{service_id}` ke liye koi logs nahi mile.", "action": "render_logs"}
                lines = []
                for item in items[-limit:]:
                    msg = item.get("message", "") if isinstance(item, dict) else str(item)
                    if msg:
                        lines.append(msg.strip())
                preview = "\n".join(lines[-40:]) or "(logs khaali hain)"
                return {"reply": f"📜 Logs for `{service_id}` (last {len(lines[-40:])} lines):\n\n```\n{preview}\n```",
                        "action": "render_logs"}
            else:
                return {"reply": f"❌ Logs fetch nahi hue: {r.text[:200]}", "action": "error"}

        elif cmd == "RENDER_SUSPEND_SERVICE":
            service_id = params["service_id"]
            r = rd_api("POST", f"/services/{service_id}/suspend")
            if r.status_code in (200, 201, 204):
                return {"reply": f"⏸️ Service `{service_id}` suspend ho gaya. Cost bachega jab tak resume na karo.",
                        "action": "render_suspend"}
            else:
                return {"reply": f"❌ Suspend Error: {r.text[:200]}", "action": "error"}

        elif cmd == "RENDER_RESUME_SERVICE":
            service_id = params["service_id"]
            r = rd_api("POST", f"/services/{service_id}/resume")
            if r.status_code in (200, 201, 204):
                return {"reply": f"▶️ Service `{service_id}` resume ho gaya.", "action": "render_resume"}
            else:
                return {"reply": f"❌ Resume Error: {r.text[:200]}", "action": "error"}

        elif cmd == "RENDER_LIST_DEPLOYS":
            service_id = params["service_id"]
            limit = params.get("limit", 10)
            r = rd_api("GET", f"/services/{service_id}/deploys?limit={limit}")
            if r.status_code == 200:
                items = r.json()
                if not items:
                    return {"reply": "Koi deploys nahi mile.", "action": "render_deploys"}
                icon_map = {"live": "✅", "build_failed": "❌", "update_failed": "❌",
                            "deactivated": "⏸️", "build_in_progress": "⏳", "update_in_progress": "⏳", "canceled": "🚫"}
                lines = []
                for item in items:
                    dep = item.get("deploy", item)
                    status = dep.get("status", "unknown")
                    icon = icon_map.get(status, "ℹ️")
                    lines.append(f"{icon} `{dep.get('id','')}` — {status} — {dep.get('createdAt','')}")
                return {"reply": f"Recent {len(items)} deploys for `{service_id}`:\n\n" + "\n".join(lines),
                        "action": "render_deploys"}
            else:
                return {"reply": f"❌ Deploy history fetch nahi hui: {r.text[:200]}", "action": "error"}

        else:
            return {"reply": f"❌ Unknown command: {cmd}", "action": "error"}

    except KeyError as e:
        return {"reply": f"❌ Required field missing: {str(e)}. Dobara try kar zyada detail ke saath.", "action": "error"}
    except json.JSONDecodeError as e:
        return {"reply": f"❌ JSON parse error: {str(e)}", "action": "error"}
    except requests.Timeout:
        return {"reply": "❌ Request timeout ho gaya. Dobara try karo 🔄", "action": "error"}
    except Exception as e:
        return {"reply": f"❌ Error: {str(e)}", "action": "error"}


# ════════════════════════════════════════════════════════════════
#  INTENT PARSER — runs on the RAW user message FIRST.
# ════════════════════════════════════════════════════════════════
SLUG = r"[\w][\w.\-]*"           # repo / project / service-ish token (no spaces)
PATH = r"[\w][\w./\-]*"          # file path token (allows slashes)

NO_ARG_COMMANDS = {"LIST_REPOS", "VERCEL_LIST_PROJECTS", "RENDER_LIST_SERVICES"}


def _g(m, i):
    """Safe group getter."""
    try:
        return m.group(i)
    except (IndexError, AttributeError):
        return None


INTENT_RULES = [
    # ── GITHUB ──
    # NOTE on ordering: more specific patterns (LIST_FILES, READ_FILE, etc.)
    # must be tried before the looser LIST_REPOS/"repo X verb" patterns below,
    # since e.g. "list files in myrepo" would otherwise satisfy LIST_REPOS's
    # loose "list ... repo?" style match first. INTENT_RULES order = priority.
    ("LIST_FILES", [
        rf"(?:list|sare|show|dikhao|dikha)\s+(?:all\s+)?files?\s+(?:in|of|from)\s+({SLUG})",
    ], lambda m: {"repo": _g(m, 1), "path": ""}),

    ("READ_FILE", [
        rf"(?:read|padh|padho|show|dikhao|dikha|open|kholo)\s+(?:the\s+)?file\s+({PATH})\s+(?:from|in|of)\s+({SLUG})",
    ], lambda m: {"repo": _g(m, 2), "path": _g(m, 1)}),

    ("DELETE_FILE", [
        rf"(?:delete|uda|udado|hata|hatao|remove)\s+(?:the\s+)?file\s+({PATH})\s+(?:from|in|of)\s+({SLUG})",
    ], lambda m: {"repo": _g(m, 2), "path": _g(m, 1)}),

    # CREATE_FILE / EDIT_FILE patterns are also matched WITHOUT trailing
    # content text — the hybrid layer decides whether AI-generated content
    # is needed based on what's left of the message.
    ("EDIT_FILE", [
        rf"(?:edit|change|update|badlo|badal\s*do|modify)\s+(?:the\s+)?file\s+({PATH})\s+(?:in|of)\s+({SLUG})",
    ], lambda m: {"repo": _g(m, 2), "path": _g(m, 1)}),

    ("CREATE_FILE", [
        rf"(?:create|bnao|banao|new|naya)\s+(?:a\s+)?file\s+({PATH})\s+(?:in|inside|for)\s+({SLUG})",
    ], lambda m: {"repo": _g(m, 2), "path": _g(m, 1)}),

    # Repo-level commands come after file-level ones (see note above),
    # so "create file X in Y" is never mistaken for "create repo Y".
    ("CREATE_REPO", [
        # verb-first WITH an extra inline Hinglish verb between "repo" and
        # the name (e.g. "naya repo banao myapp") — tried first so "banao"
        # is consumed as the verb, not captured as the repo name.
        rf"(?:create|bnao|banao|naya|new)\s+(?:a\s+|ek\s+)?repo(?:sitory)?\s+"
        rf"(?:called\s+|named\s+)?(?:bnao|banao|bana\s*do)\s+({SLUG})",
        # verb-first, simple: "create repo NAME"
        rf"(?:create|bnao|banao|naya|new)\s+(?:a\s+|ek\s+)?repo(?:sitory)?\s+(?:called\s+|named\s+)?({SLUG})",
        # verb-final: "repo NAME create karo" / "repo NAME banao"
        rf"repo(?:sitory)?\s+({SLUG})\s+(?:create|bnao|banao|bana(?:\s*do)?)\s*(?:karo|kar\s*do)?$",
    ], lambda m: {"repo": _g(m, 1)}),

    ("DELETE_REPO", [
        # verb-first
        rf"(?:delete|uda|udado|hata|hatao|remove)\s+(?:the\s+)?repo(?:sitory)?\s+({SLUG})",
        # verb-final: "mera repo NAME delete kardo" / "repo NAME uda do"
        rf"repo(?:sitory)?\s+({SLUG})\s+(?:delete|uda(?:\s*do)?|hata(?:o|\s*do)?|remove)\s*(?:karo|kar\s*do)?$",
    ], lambda m: {"repo": _g(m, 1)}),

    # ── GITHUB: branches / PRs / commits / issues / repo-meta ──
    # All inserted here (after DELETE_REPO, before LIST_REPOS) because
    # LIST_REPOS below has the loosest GitHub pattern (bare ".*\brepos?\b")
    # and must stay last in the GitHub block per existing convention.
    ("CREATE_BRANCH", [
        # verb-first: "create branch NAME in REPO"
        rf"(?:create|bnao|banao|naya|new)\s+(?:a\s+)?branch\s+({SLUG})\s+(?:in|for|of)\s+({SLUG})",
    ], lambda m: {"branch": _g(m, 1), "repo": _g(m, 2)}),

    ("CREATE_BRANCH", [
        # verb-final: "REPO me branch NAME banao" / "...create karo"
        rf"({SLUG})\s+me\s+branch\s+({SLUG})\s+(?:banao|bnao|create\s*karo|bana\s*do)",
    ], lambda m: {"repo": _g(m, 1), "branch": _g(m, 2)}),

    ("DELETE_BRANCH", [
        # verb-first: "delete branch NAME from REPO"
        rf"(?:delete|uda|udado|hata|hatao|remove)\s+(?:the\s+)?branch\s+({SLUG})\s+(?:from|in|of)\s+({SLUG})",
    ], lambda m: {"branch": _g(m, 1), "repo": _g(m, 2)}),

    ("DELETE_BRANCH", [
        # verb-final: "REPO se branch NAME hatao" / "...delete karo"
        rf"({SLUG})\s+se\s+branch\s+({SLUG})\s+(?:hatao|uda(?:o|\s*do)?|delete\s*karo)",
    ], lambda m: {"repo": _g(m, 1), "branch": _g(m, 2)}),

    ("CREATE_PR", [
        # verb-first: "create pr from HEAD to BASE in REPO"
        rf"(?:create|bnao|banao|naya|new)\s+(?:a\s+)?(?:pr|pull\s*request)\s+"
        rf"from\s+({SLUG})\s+to\s+({SLUG})\s+(?:in|for|of)\s+({SLUG})",
    ], lambda m: {"head": _g(m, 1), "base": _g(m, 2), "repo": _g(m, 3)}),

    ("CREATE_PR", [
        # verb-final: "REPO me HEAD se BASE me pr banao"
        rf"({SLUG})\s+me\s+({SLUG})\s+se\s+({SLUG})\s+me\s+(?:pr|pull\s*request)\s+(?:banao|bnao|bana\s*do)",
    ], lambda m: {"repo": _g(m, 1), "head": _g(m, 2), "base": _g(m, 3)}),

    ("MERGE_PR", [
        # verb-first: "merge pr 5 in REPO"
        rf"merge\s+(?:pr|pull\s*request)\s+#?(\d+)\s+(?:in|for|of)\s+({SLUG})",
    ], lambda m: {"pr_number": _int_or_none(_g(m, 1)), "repo": _g(m, 2)}),

    ("MERGE_PR", [
        # verb-final: "REPO me pr 5 merge karo"
        rf"({SLUG})\s+me\s+(?:pr|pull\s*request)\s+#?(\d+)\s+merge\s*(?:karo|kar\s*do)?",
    ], lambda m: {"repo": _g(m, 1), "pr_number": _int_or_none(_g(m, 2))}),

    ("LIST_COMMITS", [
        rf"(?:list|sare|show|dikhao|dikha)\s+(?:the\s+)?commits?\s+(?:in|of|for)\s+({SLUG})",
        rf"({SLUG})\s+ke\s+commits?\s+(?:dikhao|dikha|show|list)",
    ], lambda m: {"repo": _g(m, 1)}),

    ("CREATE_ISSUE", [
        # basic case only — title as a single SLUG-like token; anything with
        # extra descriptive text falls through to AI per rule 7.
        rf"(?:create|bnao|banao|naya|new)\s+(?:an?\s+)?issue\s+({SLUG})\s+(?:in|for|of)\s+({SLUG})",
    ], lambda m: {"title": _g(m, 1), "repo": _g(m, 2)}),

    ("CREATE_ISSUE", [
        rf"({SLUG})\s+me\s+issue\s+({SLUG})\s+(?:banao|bnao|bana\s*do)",
    ], lambda m: {"repo": _g(m, 1), "title": _g(m, 2)}),

    ("GET_REPO_INFO", [
        rf"(?:info|information|details)\s+(?:about|of|for)\s+(?:repo\s+)?({SLUG})",
        rf"repo\s+info\s+({SLUG})",
        rf"({SLUG})\s+ki\s+info\s+(?:do|dikhao|dikha)",
    ], lambda m: {"repo": _g(m, 1)}),

    ("RENAME_REPO", [
        # verb-first: "rename OLD to NEW"
        rf"rename\s+(?:repo\s+)?({SLUG})\s+to\s+({SLUG})",
    ], lambda m: {"repo": _g(m, 1), "new_name": _g(m, 2)}),

    ("RENAME_REPO", [
        # verb-final: "OLD ka naam NEW karo"
        rf"({SLUG})\s+ka\s+naam\s+({SLUG})\s+(?:karo|kar\s*do)",
    ], lambda m: {"repo": _g(m, 1), "new_name": _g(m, 2)}),

    ("TOGGLE_REPO_VISIBILITY", [
        # verb-first: "make REPO private" / "make REPO public"
        rf"(?:make|set)\s+({SLUG})\s+(private|public)",
    ], lambda m: {"repo": _g(m, 1), "private": _g(m, 2) == "private"}),

    ("TOGGLE_REPO_VISIBILITY", [
        # verb-final: "REPO ko private karo" / "REPO ko public karo"
        rf"({SLUG})\s+ko\s+(private|public)\s*(?:karo|kar\s*do)?",
    ], lambda m: {"repo": _g(m, 1), "private": _g(m, 2) == "private"}),

    ("ADD_COLLABORATOR", [
        # verb-first: "add USERNAME to REPO" / "add USERNAME as collaborator to REPO"
        rf"add\s+({SLUG})\s+(?:to|as\s+collaborator\s+(?:to|on|in))\s+({SLUG})",
    ], lambda m: {"username": _g(m, 1), "repo": _g(m, 2)}),

    ("ADD_COLLABORATOR", [
        # verb-final: "REPO me USERNAME ko collaborator banao"
        rf"({SLUG})\s+me\s+({SLUG})\s+ko\s+collaborator\s+(?:banao|bnao|bana\s*do|add\s*karo)",
    ], lambda m: {"repo": _g(m, 1), "username": _g(m, 2)}),

    ("LIST_REPOS", [
        r"(?:list|sare|mere|show|dikhao|dikha)\s+.*\brepos?\b",
        r"^(?:repos?|my\s+repos?)$",
    ], lambda m: {}),

    # ── VERCEL ──
    ("VERCEL_LIST_PROJECTS", [
        r"(?:list|sare|show|dikhao|dikha)\s+.*vercel.*projects?\b",
        r"^vercel\s+projects?$",
    ], lambda m: {}),

    ("VERCEL_IMPORT_REPO", [
        rf"(?:import|connect)\s+({SLUG})\s+(?:to|pe|on|with)\s+vercel",
    ], lambda m: {"repo": _g(m, 1)}),

    ("VERCEL_DEPLOY", [
        rf"deploy\s+({SLUG})\s+(?:to|pe|on)\s+vercel",
    ], lambda m: {"project_name": _g(m, 1)}),

    ("VERCEL_DELETE_PROJECT", [
        rf"(?:delete|uda|hata)\s+vercel\s+project\s+({SLUG})",
    ], lambda m: {"project_name": _g(m, 1)}),

    # ── VERCEL: env / domain / deployments / rollback / logs ──
    # Inserted here, before VERCEL_DEPLOY_STATUS's loose "status/check ...
    # SLUG" pattern, since GET_LOGS/LIST_DEPLOYMENTS use distinct keywords
    # ("logs", "deployments") that could otherwise be swallowed by a
    # generic "check X" style match if that rule came first.
    ("VERCEL_GET_ENV", [
        rf"(?:get|show|dikhao|dikha)\s+.*env(?:ironment)?(?:\s+vars?)?\s+(?:for|of)\s+({SLUG})\s+.*vercel",
        rf"vercel\s+.*env(?:ironment)?(?:\s+vars?)?\s+(?:for|of)\s+({SLUG})",
    ], lambda m: {"project_name": _g(m, 1)}),

    ("VERCEL_GET_ENV", [
        rf"({SLUG})\s+(?:ka|ke)\s+env\s+(?:dikhao|dikha|show)\s+vercel",
    ], lambda m: {"project_name": _g(m, 1)}),

    # NOTE: env var KEY casing is restored from the original (non-lowered)
    # message in parse_intent() below — same fix as RENDER_SET_ENV, since
    # env keys are conventionally uppercase and case-sensitive on Vercel.
    ("VERCEL_SET_ENV", [
        rf"(?:set|add|update)\s+env\s+(\w+)\s*=\s*(\S+)\s+(?:for|in|on)\s+({SLUG})\s+.*vercel",
        rf"(?:set|add|update)\s+vercel\s+env\s+(\w+)\s*=\s*(\S+)\s+(?:for|in|on)\s+({SLUG})",
    ], lambda m: {"project_name": _g(m, 3), "key": _g(m, 1), "value": _g(m, 2)}),

    ("VERCEL_ADD_DOMAIN", [
        # verb-first: "add domain example.com to PROJECT"
        rf"add\s+domain\s+({SLUG})\s+(?:to|for|on)\s+({SLUG})",
    ], lambda m: {"domain": _g(m, 1), "project_name": _g(m, 2)}),

    ("VERCEL_ADD_DOMAIN", [
        # verb-final: "PROJECT me domain example.com jodo"
        rf"({SLUG})\s+(?:me|pe)\s+domain\s+({SLUG})\s+(?:add\s*karo|jodo|jod\s*do)",
    ], lambda m: {"project_name": _g(m, 1), "domain": _g(m, 2)}),

    ("VERCEL_LIST_DEPLOYMENTS", [
        rf"(?:list|sare|show|dikhao|dikha)\s+(?:the\s+)?deployments?\s+(?:of|for)\s+({SLUG})",
        rf"({SLUG})\s+ke\s+deployments?\s+(?:dikhao|dikha|show|list)",
    ], lambda m: {"project_name": _g(m, 1)}),

    ("VERCEL_ROLLBACK", [
        # negative lookahead excludes bare "karo"/"kar do" from being
        # swallowed as the deployment_id when the verb-first pattern is
        # matched against a verb-final phrase like "... rollback karo".
        rf"rollback\s+(?:to\s+)?(?!karo\b|kar\s*do\b)({SLUG})",
        rf"({SLUG})\s+pe\s+rollback\s*(?:karo|kar\s*do)?",
    ], lambda m: {"deployment_id": _g(m, 1)}),

    ("VERCEL_GET_LOGS", [
        rf"(?:get|show|dikhao|dikha)\s+(?:the\s+)?logs?\s+(?:for|of)\s+({SLUG})\s+.*vercel",
        rf"vercel\s+logs?\s+(?:for|of)\s+({SLUG})",
    ], lambda m: {"deployment_id": _g(m, 1)}),

    ("VERCEL_GET_LOGS", [
        rf"({SLUG})\s+ke\s+vercel\s+logs?\s+(?:dikhao|dikha|show)",
    ], lambda m: {"deployment_id": _g(m, 1)}),

    ("VERCEL_DEPLOY_STATUS", [
        rf"(?:status|check)\s+(?:deploy(?:ment)?\s+)?(?:status\s+)?(?:of\s+)?({SLUG})",
    ], lambda m: {"deployment_id": _g(m, 1)}),

    # ── RENDER ──
    ("RENDER_LIST_SERVICES", [
        r"(?:list|sare|show|dikhao|dikha)\s+.*render.*services?\b",
        r"(?:list|sare|show|dikhao|dikha)\s+.*services?.*render\b",
        r"^render\s+services?$",
        r"^services?\s+render$",
        # verb-final: "render services dikhao" / "render ke services dikha"
        r"^render\s+(?:ke\s+)?services?\s+(?:dikhao|dikha|show|list)$",
    ], lambda m: {}),

    ("RENDER_GET_ENV", [
        rf"(?:get|show|dikhao|dikha)\s+.*env(?:ironment)?(?:\s+vars?)?\s+(?:for|of)\s+({SLUG})",
    ], lambda m: {"service_id": _g(m, 1)}),

    # NOTE: env var KEY casing is restored from the original (non-lowered)
    # message in parse_intent() below — env keys are conventionally uppercase
    # and lowercasing them here would silently break the actual API call.
    ("RENDER_SET_ENV", [
        rf"(?:set|add|update)\s+env\s+(\w+)\s*=\s*(\S+)\s+(?:for|in|on)\s+({SLUG})",
    ], lambda m: {"service_id": _g(m, 3), "env_vars": {_g(m, 1): _g(m, 2)}}),

    ("RENDER_DEPLOY", [
        rf"deploy\s+({SLUG})\s+(?:to|pe|on)\s+render",
    ], lambda m: {"service_id": _g(m, 1)}),

    # ── RENDER: delete / create / logs / suspend / resume / deploy-history ──
    # RENDER_LIST_SERVICES above already requires "services" explicitly, so
    # RENDER_LIST_DEPLOYS (requiring "deploys") can't collide with it
    # regardless of position, but is kept last in this group for readability.
    ("RENDER_DELETE_SERVICE", [
        rf"(?:delete|uda|udado|hata|hatao|remove)\s+(?:the\s+)?(?:render\s+)?service\s+({SLUG})",
    ], lambda m: {"service_id": _g(m, 1)}),

    ("RENDER_DELETE_SERVICE", [
        rf"({SLUG})\s+service\s+(?:delete|uda(?:o|\s*do)?|hata(?:o|\s*do)?)\s*(?:karo|kar\s*do)?",
    ], lambda m: {"service_id": _g(m, 1)}),

    ("RENDER_CREATE_SERVICE", [
        # basic case only — complex options (plan/env/build cmd) fall through
        # to AI per rule 7.
        rf"(?:create|bnao|banao|naya|new)\s+(?:a\s+)?render\s+service\s+(?:from|for)\s+({SLUG})",
    ], lambda m: {"repo": _g(m, 1)}),

    ("RENDER_CREATE_SERVICE", [
        rf"({SLUG})\s+se\s+render\s+service\s+(?:banao|bnao|bana\s*do)",
    ], lambda m: {"repo": _g(m, 1)}),

    ("RENDER_GET_LOGS", [
        rf"(?:get|show|dikhao|dikha)\s+(?:the\s+)?logs?\s+(?:for|of)\s+({SLUG})\s+.*render",
        rf"render\s+logs?\s+(?:for|of)\s+({SLUG})",
    ], lambda m: {"service_id": _g(m, 1)}),

    ("RENDER_GET_LOGS", [
        rf"({SLUG})\s+ke\s+render\s+logs?\s+(?:dikhao|dikha|show)",
    ], lambda m: {"service_id": _g(m, 1)}),

    ("RENDER_SUSPEND_SERVICE", [
        rf"suspend\s+(?:the\s+)?(?:render\s+)?service\s+({SLUG})",
        rf"({SLUG})\s+(?:ko\s+)?suspend\s*(?:karo|kar\s*do)?",
    ], lambda m: {"service_id": _g(m, 1)}),

    ("RENDER_RESUME_SERVICE", [
        rf"resume\s+(?:the\s+)?(?:render\s+)?service\s+({SLUG})",
        rf"({SLUG})\s+(?:ko\s+)?resume\s*(?:karo|kar\s*do)?",
    ], lambda m: {"service_id": _g(m, 1)}),

    ("RENDER_LIST_DEPLOYS", [
        rf"(?:list|sare|show|dikhao|dikha)\s+(?:the\s+)?deploys?\s+(?:of|for)\s+({SLUG})",
        rf"({SLUG})\s+ke\s+deploys?\s+(?:dikhao|dikha|show|list)",
    ], lambda m: {"service_id": _g(m, 1)}),
]
# Keywords that signal the user wants generated content/explanation rather
# than a direct API action — even if a structural pattern also matches
# (e.g. "create file index.html in test with navbar" matches CREATE_FILE's
# structure AND contains "navbar", which needs AI to write the navbar).
COMPLEX_KEYWORDS = [
    "likh", "likho", "banao", "banado", "bnado", "code", "html", "css", "js",
    "javascript", "script", "function", "explain", "samjha", "samjhao",
    "kaise", "kyu", "kyun", "kya", "write", "generate", "design", "navbar",
    "component", "snippet", "fix kar", "debug",
]


def detect_complex(message):
    """Detect complex-intent keywords, but ignore matches that are just a file
    extension embedded in a filename/path (e.g. 'index.html', 'old.js') —
    those aren't a request for AI-generated content by themselves."""
    lowered = message.lower()
    # Strip anything that looks like a bare filename/path token so extensions
    # like ".html" / ".js" / ".css" inside them don't trip the keyword scan.
    stripped = re.sub(r"\b[\w][\w./-]*\.(?:html|css|js|py|json|md|txt|yml|yaml)\b", " ", lowered)
    return any(re.search(rf"\b{re.escape(kw)}", stripped) for kw in COMPLEX_KEYWORDS)


def parse_intent(message):
    """Try every structural rule against the raw (lowercased) user message.
    Returns (cmd, params) on first match, or (None, None) if nothing matches."""
    original = message.strip()
    lowered = original.lower()
    for cmd, patterns, extractor in INTENT_RULES:
        for pat in patterns:
            m = re.search(pat, lowered)
            if m:
                try:
                    params = extractor(m)
                except Exception:
                    continue
                # Reject only when a REQUIRED identifying field came back
                # empty/None. "path" is legitimately "" for LIST_FILES (repo
                # root), so it's excluded from this required-field check.
                required_fields = {"repo", "project_name", "service_id", "deployment_id"}
                if any(params.get(f) in (None, "") for f in required_fields if f in params):
                    continue
                # RENDER_SET_ENV: env var keys are conventionally uppercase
                # and case-sensitive on the Render side. The match above ran
                # against the lowercased message, so recover the original
                # casing for the key by re-matching the same span against
                # the original (non-lowered) message.
                if cmd == "RENDER_SET_ENV":
                    orig_m = re.search(pat, original, re.IGNORECASE)
                    if orig_m:
                        real_key = orig_m.group(1)
                        params["env_vars"] = {real_key: params["env_vars"][list(params["env_vars"].keys())[0]]}
                return cmd, params
    return None, None


# ════════════════════════════════════════════════════════════════
#  AI — two separate call paths:
#   1. call_openrouter_chat()  — full conversational agent, used ONLY when
#      the regex parser finds nothing and the message isn't a direct command.
#   2. call_openrouter_codegen() — lean, single-purpose prompt that ONLY
#      returns raw file content, used by the CREATE_FILE/EDIT_FILE hybrid path.
# ════════════════════════════════════════════════════════════════
OPENROUTER_MODEL = "nvidia/nemotron-3-super-120b-a12b:free"

SYSTEM_PROMPT = f"""You are a powerful Multi-Cloud DevOps Agent for user: {GITHUB_USERNAME}.
You control three platforms: GitHub (source code), Vercel (frontend deploys), and Render (backend/web services + databases).

You act by outputting EXACTLY ONE command per response. Never combine commands. Never add commentary before or after a command.

──────────────── GITHUB COMMANDS ────────────────

1. CREATE_REPO: <repo-name>
2. DELETE_REPO: <repo-name>
3. LIST_REPOS
4. CREATE_FILE: {{"repo":"repo-name","path":"folder/file.html","content":"full file content here","message":"commit message"}}
5. READ_FILE: {{"repo":"repo-name","path":"file.html"}}
6. EDIT_FILE: {{"repo":"repo-name","path":"file.html","content":"updated full content","message":"what changed"}}
7. DELETE_FILE: {{"repo":"repo-name","path":"file.html","message":"reason"}}
8. LIST_FILES: {{"repo":"repo-name","path":""}}
9. CREATE_BRANCH: {{"repo":"repo-name","branch":"new-branch","base":"main"}}
10. DELETE_BRANCH: {{"repo":"repo-name","branch":"branch-name"}}
11. CREATE_PR: {{"repo":"repo-name","head":"feature-branch","base":"main","title":"PR title","body":"description"}}
12. MERGE_PR: {{"repo":"repo-name","pr_number":12,"merge_method":"merge"}}
13. LIST_COMMITS: {{"repo":"repo-name","branch":"main","limit":10}}
14. CREATE_ISSUE: {{"repo":"repo-name","title":"issue title","body":"description"}}
15. GET_REPO_INFO: {{"repo":"repo-name"}}
16. RENAME_REPO: {{"repo":"old-name","new_name":"new-name"}}
17. TOGGLE_REPO_VISIBILITY: {{"repo":"repo-name","private":true}}
18. ADD_COLLABORATOR: {{"repo":"repo-name","username":"github-user","permission":"push"}}

──────────────── VERCEL COMMANDS ────────────────

19. VERCEL_LIST_PROJECTS
20. VERCEL_IMPORT_REPO: {{"repo":"repo-name","project_name":"optional-custom-name","framework":"optional-framework-preset"}}
21. VERCEL_DEPLOY: {{"project_name":"project-name"}}
22. VERCEL_DEPLOY_STATUS: {{"deployment_id":"dpl_xxx"}}
23. VERCEL_DELETE_PROJECT: {{"project_name":"project-name"}}
24. VERCEL_GET_ENV: {{"project_name":"project-name"}}
25. VERCEL_SET_ENV: {{"project_name":"project-name","key":"KEY","value":"value","target":["production","preview","development"]}}
26. VERCEL_ADD_DOMAIN: {{"project_name":"project-name","domain":"example.com"}}
27. VERCEL_LIST_DEPLOYMENTS: {{"project_name":"project-name","limit":10}}
28. VERCEL_ROLLBACK: {{"deployment_id":"dpl_xxx"}}
29. VERCEL_GET_LOGS: {{"deployment_id":"dpl_xxx","limit":50}}

──────────────── RENDER COMMANDS ────────────────

30. RENDER_LIST_SERVICES
31. RENDER_GET_ENV: {{"service_id":"srv-xxx"}}
32. RENDER_SET_ENV: {{"service_id":"srv-xxx","env_vars":{{"KEY":"value"}}}}
33. RENDER_DEPLOY: {{"service_id":"srv-xxx","clear_cache":true}}
34. RENDER_DELETE_SERVICE: {{"service_id":"srv-xxx"}}
35. RENDER_CREATE_SERVICE: {{"repo":"repo-name","name":"service-name","type":"web_service","env":"node","plan":"free","branch":"main","build_command":"","start_command":""}}
36. RENDER_GET_LOGS: {{"service_id":"srv-xxx","limit":50}}
37. RENDER_SUSPEND_SERVICE: {{"service_id":"srv-xxx"}}
38. RENDER_RESUME_SERVICE: {{"service_id":"srv-xxx"}}
39. RENDER_LIST_DEPLOYS: {{"service_id":"srv-xxx","limit":10}}

──────────────── RULES ────────────────

- Output ONLY the command, nothing else before or after it, UNLESS the user's
  request is conversational / explanatory / asks you to write code inline in
  chat rather than commit it — in that case respond normally with no command.
- JSON must be valid — no trailing commas, proper double quotes.
- For code in content field, escape double quotes as \\" and newlines as \\n.
- Always write complete working code, never truncate.
- You have full context of the conversation above. Use repo/project/service names
  mentioned earlier if the user refers back to them ("that repo", "the service", "it").

──────────────── ABSOLUTE ANTI-HALLUCINATION RULE ────────────────

You have NO knowledge of real deployment IDs, live URLs, service IDs, API keys, environment variable values, or any other infrastructure state. ALL of that only exists in the actual GitHub/Vercel/Render APIs, which you can reach ONLY by emitting one of the 17 commands above.

- NEVER write a deployment ID, project URL, service ID, status, or env var value yourself. If you don't have one of the 17 commands to run, you do not have this information — say so plainly instead of inventing it.
- NEVER format your own conversational text to look like a tool result (no fake ✅/❌ icons, no fake "Status:", "Deployment ID:", "Live URL:" labels, no fake code blocks claiming to be API output) unless you are literally emitting one of the 17 commands for the system to execute.
- NEVER output anything that resembles a real secret, token, or API key under any circumstance, even as an example or placeholder. Use literal text like <your-token-here> for placeholders.
- If you are not emitting a command, your entire response must be plain conversational text with no fabricated data points standing in for real ones.
"""

CODEGEN_SYSTEM_PROMPT = """You generate file content for a developer tool. You will be given a short instruction describing a file to create or update.

Rules:
- Output ONLY the raw file content. No markdown code fences, no explanation, no preamble, no "Here's the code" — just the file's exact contents from the first character to the last.
- Write complete, working, production-quality code. Never truncate, never use placeholders like "// rest of code here".
- Infer the file type/language from the file path and instruction (e.g. .html, .css, .js, .py).
- If the instruction is in Hinglish, still produce clean code with English identifiers/comments unless told otherwise.
"""

COMMANDS = [
    "CREATE_REPO:", "DELETE_REPO:", "LIST_REPOS", "CREATE_FILE:",
    "READ_FILE:", "EDIT_FILE:", "DELETE_FILE:", "LIST_FILES:",
    "CREATE_BRANCH:", "DELETE_BRANCH:", "CREATE_PR:", "MERGE_PR:",
    "LIST_COMMITS:", "CREATE_ISSUE:", "GET_REPO_INFO:", "RENAME_REPO:",
    "TOGGLE_REPO_VISIBILITY:", "ADD_COLLABORATOR:",
    "VERCEL_LIST_PROJECTS", "VERCEL_IMPORT_REPO:", "VERCEL_DEPLOY:", "VERCEL_DEPLOY_STATUS:",
    "VERCEL_DELETE_PROJECT:", "VERCEL_GET_ENV:", "VERCEL_SET_ENV:", "VERCEL_ADD_DOMAIN:",
    "VERCEL_LIST_DEPLOYMENTS:", "VERCEL_ROLLBACK:", "VERCEL_GET_LOGS:",
    "RENDER_LIST_SERVICES", "RENDER_GET_ENV:", "RENDER_SET_ENV:", "RENDER_DEPLOY:",
    "RENDER_DELETE_SERVICE:", "RENDER_CREATE_SERVICE:", "RENDER_GET_LOGS:",
    "RENDER_SUSPEND_SERVICE:", "RENDER_RESUME_SERVICE:", "RENDER_LIST_DEPLOYS:",
]


def looks_fabricated(text):
    """Heuristic: does this free-text AI response impersonate a real tool result
    instead of an honest conversational answer?"""
    fabrication_markers = [
        r"deployment\s*id\s*:", r"deploy\s*id\s*:", r"dpl_[a-z0-9]{6,}",
        r"live\s*url\s*:", r"status\s*:\s*\*?\*?ready", r"srv-[a-z0-9]{6,}",
        r"trigger\s*ho\s*gaya", r"deploy\s*trigger\s*ho\s*gaya", r"successful\s*hai",
    ]
    lowered = text.lower()
    hits = sum(1 for pat in fabrication_markers if re.search(pat, lowered))
    return hits >= 2


def extract_command(text):
    """Extract a single command (and its payload) from an AI agent response.
    Returns (command_name, raw_value_or_None)."""
    text = text.strip()
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


def call_openrouter_chat(user_message, history):
    """Full conversational agent path — used only when regex parsing finds
    nothing usable. May return either a command string or plain conversation."""
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    for h in history[-10:]:
        messages.append({"role": h["role"], "content": h["content"]})
    messages.append({"role": "user", "content": user_message})

    ai_resp = requests.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {OPENROUTER_KEY}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github-agent-r7rn.onrender.com",
            "X-Title": "Multi-Cloud DevOps Agent"
        },
        json={"model": OPENROUTER_MODEL, "messages": messages, "temperature": 0.2},
        timeout=30
    ).json()

    if "error" in ai_resp:
        raise RuntimeError(ai_resp["error"].get("message", "Unknown AI error"))

    return ai_resp["choices"][0]["message"]["content"].strip()


def call_openrouter_codegen(instruction, path_hint=""):
    """Lean code-generation-only call. Returns raw file content as a string."""
    user_prompt = f"File path: {path_hint}\n\nInstruction: {instruction}" if path_hint else instruction

    ai_resp = requests.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {OPENROUTER_KEY}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github-agent-r7rn.onrender.com",
            "X-Title": "Multi-Cloud DevOps Agent - Codegen"
        },
        json={
            "model": OPENROUTER_MODEL,
            "messages": [
                {"role": "system", "content": CODEGEN_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.3,
        },
        timeout=45
    ).json()

    if "error" in ai_resp:
        raise RuntimeError(ai_resp["error"].get("message", "Unknown AI error"))

    content = ai_resp["choices"][0]["message"]["content"].strip()
    content = re.sub(r"^```[\w]*\n", "", content)
    content = re.sub(r"\n```$", "", content)
    return content


# ════════════════════════════════════════════════════════════════
#  HYBRID HANDLER — CREATE_FILE / EDIT_FILE
# ════════════════════════════════════════════════════════════════
def handle_create_or_edit_file(cmd, params, user_message):
    instruction = user_message.strip()
    ai_content = call_openrouter_codegen(instruction, path_hint=params.get("path", ""))
    full_params = {
        "repo": params["repo"],
        "path": params["path"],
        "content": ai_content,
        "message": f"{'Update' if cmd == 'EDIT_FILE' else 'Add'} {params['path']} via DevOps Agent",
    }
    result = execute_command(cmd, full_params)
    result["source"] = "hybrid"
    return result


# ════════════════════════════════════════════════════════════════
#  ROUTES
# ════════════════════════════════════════════════════════════════
@app.route("/")
def home():
    return send_from_directory(".", "index.html")


@app.route("/chat", methods=["POST"])
def chat():
    body = request.json or {}

    # 1. CONFIRMED DESTRUCTIVE ACTION REPLAY
    if body.get("confirmed"):
        cmd = body.get("pending_command")
        value = body.get("pending_value")
        token = body.get("confirm_token")
        if cmd not in DESTRUCTIVE_COMMANDS or token != confirm_token(cmd, value):
            return safe_jsonify({"reply": "❌ Confirmation token match nahi hua. Dobara try kar.", "action": "error", "source": "direct"})
        try:
            params = json.loads(value) if value else {}
        except (json.JSONDecodeError, TypeError):
            params = {}
        result = execute_command(cmd, params)
        result["source"] = "direct"
        return safe_jsonify(result)

    user_message = body.get("message", "").strip()
    history = body.get("history", [])

    if not user_message:
        return safe_jsonify({"reply": "Kuch toh bol bhai 😅", "action": None, "source": "direct"})

    # 2. STRUCTURAL INTENT MATCH (regex over raw user message)
    cmd, params = parse_intent(user_message)

    if cmd:
        if cmd in ("CREATE_FILE", "EDIT_FILE"):
            try:
                result = handle_create_or_edit_file(cmd, params, user_message)
                return safe_jsonify(result)
            except RuntimeError as e:
                return safe_jsonify({"reply": f"❌ AI Error: {str(e)}", "action": "error", "source": "hybrid"})
            except requests.Timeout:
                return safe_jsonify({"reply": "AI ne content generate karne me bahut time lagaya. Dobara try karo 🔄", "action": "error", "source": "hybrid"})
            except Exception as e:
                return safe_jsonify({"reply": f"❌ Error: {str(e)}", "action": "error", "source": "hybrid"})

        if cmd in DESTRUCTIVE_COMMANDS:
            return safe_jsonify(build_confirmation(cmd, params))

        result = execute_command(cmd, params)
        result["source"] = "direct"
        result["action_command"] = cmd
        return safe_jsonify(result)

    # 3. NO STRUCTURAL MATCH → AI FALLBACK (full conversational agent)
    try:
        ai_text = call_openrouter_chat(user_message, history)
    except RuntimeError as e:
        return safe_jsonify({"reply": f"AI Error: {str(e)}", "action": "error", "source": "ai"})
    except requests.Timeout:
        return safe_jsonify({"reply": "AI ne jawab dene me bahut time lagaya. Dobara try karo 🔄", "action": "error", "source": "ai"})
    except Exception as e:
        return safe_jsonify({"reply": f"AI connection error: {str(e)}", "action": "error", "source": "ai"})

    ai_cmd, ai_value = extract_command(ai_text)

    if ai_cmd:
        if ai_cmd in NO_ARG_COMMANDS:
            ai_params = {}
        else:
            try:
                if ai_value and ai_value.strip().startswith("{"):
                    ai_params = json.loads(ai_value)
                elif ai_cmd in ("CREATE_REPO", "DELETE_REPO"):
                    ai_params = {"repo": (ai_value or "").strip()}
                elif ai_cmd == "VERCEL_DELETE_PROJECT":
                    ai_params = {"project_name": (ai_value or "").strip()}
                else:
                    ai_params = {}
            except json.JSONDecodeError:
                return safe_jsonify({"reply": "❌ AI ne sahi JSON nahi diya. Dobara try karo.", "action": "error", "source": "ai"})

        if ai_cmd in DESTRUCTIVE_COMMANDS:
            return safe_jsonify(build_confirmation(ai_cmd, ai_params))

        result = execute_command(ai_cmd, ai_params)
        result["source"] = "ai"
        result["action_command"] = ai_cmd
        return safe_jsonify(result)

    # Plain conversational AI response — no command emitted.
    if looks_fabricated(ai_text):
        return safe_jsonify({
            "reply": "⚠️ Mujhe ek real command run karna chahiye tha is request ke liye, "
                     "lekin maine galti se ek fake-looking response generate kar diya tha jo block ho gaya. "
                     "Dobara try kar — agar specific repo/project/service ka naam bata de to main sahi command chalaunga.",
            "action": "warning", "source": "ai"
        })
    return safe_jsonify({"reply": ai_text, "action": "message", "source": "ai"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
