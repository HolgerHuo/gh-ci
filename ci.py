import os
import tempfile
import shutil
import hmac
import hashlib
import subprocess
import zipfile
import logging
import json
import threading

import requests
from flask import Flask, request, jsonify, abort

app = Flask(__name__)

gunicorn_logger = logging.getLogger("gunicorn.error")
app.logger.handlers = gunicorn_logger.handlers
app.logger.setLevel(gunicorn_logger.level)

GITHUB_SECRET = b"github_secret_for_verifying_webhook"
GITHUB_TOKEN = "personal_access_token_to_update_commit_status"
CADDY_API_URL = "caddy_api_for_hot_reloading"

def update_caddy(root):
    response = requests.post(CADDY_API_URL, data=f'"{root}"', headers={"Content-Type": "application/json"})

    if response.status_code == 200:
        app.logger.debug(f"updated caddy root to: {root}")
    else:
        raise Exception(f"failed to update caddy: {response.text}")

def verify_signature(payload, signature_header):
    if not signature_header:
        return False

    app.logger.debug(f"received signature_header: {signature_header}")

    hash_algo, signature = signature_header.split('=')
    digest = hmac.new(GITHUB_SECRET, payload, hashlib.sha256).hexdigest()

    return hmac.compare_digest(digest, signature)

def update_github_status(repo, sha, state, description):
    url = f"https://api.github.com/repos/{repo}/statuses/{sha}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json"}
    data = {"state": state, "description": description, "context": "Deployment"}

    response = requests.post(url, json=data, headers=headers)
    if response.status_code == 201:
        app.logger.debug(f"github status updated: {state}")
    else:
        app.logger.error(f"failed to update github status: {response.json()}")

@app.route("/ci", methods=["POST"])
def ci():
    payload = request.get_data()
    signature_header = request.headers.get("X-Hub-Signature-256")
    if not verify_signature(payload, signature_header):
        app.logger.debug("unauthorized request")
        abort(403)

    data = request.json
    if not "head_commit" in data or data["ref"] != "refs/heads/main":
        return jsonify({"message": "ignoring request"}), 200

    def build(**kwargs):
        data = kwargs.get('data', {})

        repo_full_name = data["repository"]["full_name"]
        commit_sha = data["head_commit"]["id"]
        zip_url = data["repository"]["archive_url"].replace("{archive_format}{/ref}", f"zipball/{commit_sha}")

        app.logger.info(f"building repo: {repo_full_name}, commit: {commit_sha}")

        update_github_status(repo_full_name, commit_sha, "pending", "Deployment started")

        temp_dir = tempfile.mkdtemp()

        try:
            zip_path = os.path.join(temp_dir, "repo.zip")
            headers = {"Authorization": f"token {GITHUB_TOKEN}"}
            response = requests.get(zip_url, headers=headers, stream=True)

            if response.status_code == 200:
                with open(zip_path, "wb") as f:
                    for chunk in response.iter_content(1024):
                        f.write(chunk)
                app.logger.debug("downloaded repository")
            else:
                update_github_status(repo_full_name, commit_sha, "failure", "Failed to download repository")
                raise Exception(f"failed to download repository, status code: {response.status_code}")

            if not zipfile.is_zipfile(zip_path):
                update_github_status(repo_full_name, commit_sha, "failure", "Failed to download repository")
                raise Exception("invalid downloaded file")

            extract_dir = os.path.join(temp_dir, "repo")
            shutil.unpack_archive(zip_path, extract_dir)
            app.logger.debug("extracted repository")

            root_folder = next(os.scandir(extract_dir)).path
            commands = ["bun install", "bun run build"]

            for cmd in commands:
                app.logger.debug(f"running: {cmd}")
                result = subprocess.run(cmd, shell=True, cwd=root_folder, capture_output=True, text=True)
                app.logger.debug(result.stdout)
                if result.returncode != 0:
                    update_github_status(repo_full_name, commit_sha, "failure", f"Running command: {cmd} failed")
                    raise Exception(f"failed to run command: {cmd}")

            dest="/home/ci/dist"
            src=root_folder+"/dist/static"

            try:
                backup_dir = dest + ".bak"
                if os.path.exists(dest):
                    if os.path.exists(backup_dir):
                        shutil.rmtree(backup_dir)
                    shutil.copytree(dest, backup_dir)
                    update_caddy(backup_dir)
                    shutil.rmtree(dest)
                
                os.rename(src, dest)
                update_caddy(dest)
                if os.path.exists(backup_dir):
                    shutil.rmtree(backup_dir)

            except Exception as e:
                raise e

            update_github_status(repo_full_name, commit_sha, "success", "Deployment successful")
            app.logger.info("deployment successful")

        except Exception as e:
            update_github_status(repo_full_name, commit_sha, "failure", "Unexpected error occurred")
            app.logger.error("deployment failed")
            app.logger.debug(e)

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
            app.logger.debug(f"cleaned up temporary directory: {temp_dir}")
        
    thread = threading.Thread(target=build, kwargs={'data': data})
    thread.start()
    return {"message": "accepted"}, 202

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
