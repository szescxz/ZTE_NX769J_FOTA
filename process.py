import dateutil
import dateutil.parser
import hashlib
import html
import os
import re
import subprocess
import sys
import tempfile
import time
import warnings

from base64 import b64decode
from email.utils import format_datetime
from zipfile import ZipFile

import requests

from utils import clear_line, DeltaUpdateFile, DownloadDescriptor, HttpFile, load_props, progress, redmagic_probe_full_ota_url, verify_package

DEVICE_MODELS = os.environ.get("DEVICE_MODELS", "NX769J,NX769S").split(",")
IS_REDMAGIC = int(os.environ.get("IS_REDMAGIC", "1"))
FILES_TO_EXTRACT = [
    "apex_info.pb",
    "build.prop",
    "care_map.pb"
]
GITHUB_REPOSITORY = os.environ.get("GITHUB_REPOSITORY", "szescxz/ZTE_NX769J_FOTA")
GITHUBUSERCONTENT_HTTP_HEADERS = {
    "user-agent": "curl/8.10.1"
}
GIT_USER_NAME = "ZTE"
GIT_USER_EMAIL = "support@zte.com.cn"
TZINFOS = {
    "CST": 8 * 3600
}

def git_commit(repo_folder, build_props):
    if len(subprocess.check_output(
        "git status --porcelain",
        stderr=subprocess.DEVNULL,
        shell=True,
        cwd=repo_folder
    )) > 0:
        build_date_string = format_datetime(dateutil.parser.parse(build_props["ro.build.date"], tzinfos=TZINFOS))
        subprocess.run(
            "git add -A",
            stderr=subprocess.DEVNULL,
            shell=True,
            cwd=repo_folder
        ).check_returncode()
        env = os.environ.copy()
        env["GIT_AUTHOR_NAME"] = GIT_USER_NAME
        env["GIT_AUTHOR_EMAIL"] = GIT_USER_EMAIL
        env["GIT_AUTHOR_DATE"] = build_date_string
        env["GIT_COMMITTER_NAME"] = GIT_USER_NAME
        env["GIT_COMMITTER_EMAIL"] = GIT_USER_EMAIL
        env["GIT_COMMITTER_DATE"] = build_date_string
        display_id = build_props["ro.build.display.id"]
        sw_internal_version = build_props["ro.build.sw_internal_version"]
        security_patch = build_props["ro.build.version.security_patch"]
        build_fingerprint = build_props["ro.system.build.fingerprint"]
        subprocess.run(
            "git commit -F -",
            stderr=subprocess.DEVNULL,
            shell=True,
            env=env,
            input=f"{display_id}\n{sw_internal_version}\n{build_fingerprint}\n{security_patch}",
            encoding="ascii",
            cwd=repo_folder
        ).check_returncode()

        subprocess.run(
            f"git tag {sw_internal_version}",
            stderr=subprocess.DEVNULL,
            shell=True,
            cwd=repo_folder
        ).check_returncode()

        subprocess.run(
            "git push",
            stderr=subprocess.DEVNULL,
            shell=True,
            cwd=repo_folder
        ).check_returncode()

        subprocess.run(
            "git push --tags",
            stderr=subprocess.DEVNULL,
            shell=True,
            cwd=repo_folder
        ).check_returncode()

def update_tracking_repository(repo_folder, ota_url):
    # Force HTTPS here; let's just assume all OTAs from ZTE servers are authentic so we don't have to hash almost the entire package for signature verification
    with ZipFile(HttpFile(ota_url.replace("http://", "https://").replace(".com:80/", ".com/")), "r") as ota_file:
        with ota_file.open("build.prop", "r") as f:
            ota_build_props = load_props(f.read())
        with ota_file.open("META-INF/com/android/metadata", "r") as f:
            metadata = load_props(f.read())
        assert metadata["pre-device"] == DEVICE_MODELS[0]

        try:
            with open(os.path.join(repo_folder, "build.prop"), "r") as f:
                repo_build_props = load_props(f.read())

            if metadata["pre-build"] != repo_build_props["ro.system.build.fingerprint"] or metadata["pre-build-incremental"] != repo_build_props["ro.build.version.incremental"]:
                known_versions = subprocess.check_output("git tag", shell=True, cwd=repo_folder).decode().splitlines()
                if ota_build_props["ro.build.sw_internal_version"] in known_versions:
                    print("Target build version exists, no need to update repository")
                    return
                assert int(ota_build_props["ro.system.build.date.utc"]) > int(repo_build_props["ro.system.build.date.utc"]), "Target build is older than latest commit, cannot proceed automatically"
                warnings.warn("Source build mismatch")

            if metadata.get("ota-downgrade", None) == "yes":
                print("Downgrade package detected, no need to update repository")
                return
        except FileNotFoundError:
            pass
        
        for file in FILES_TO_EXTRACT:
            ota_file.extract(file, repo_folder)

        with ota_file.open("payload.bin", "r") as payload_file:
            payload = DeltaUpdateFile(payload_file)

            with open(os.path.join(repo_folder, "sha256sums"), "w") as f:
                for part in payload.manifest.partitions:
                    f.write(f"{part.new_partition_info.hash.hex()}  {part.partition_name}.img\n")
        
        git_commit(repo_folder, ota_build_props)

def add_package_to_github_release(ota_name, dd_url):
    with requests.Session() as session:
        def github_req(method, url_or_uri, headers={}, data=None, json=None):
            headers = dict(headers)
            headers.update({
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {os.environ.get('GITHUB_TOKEN')}",
                "X-GitHub-Api-Version": "2022-11-28"
            })

            if url_or_uri.startswith("https://"):
                url = url_or_uri
            else:
                url = f"https://api.github.com{url_or_uri}"

            return session.request(method, url, headers=headers, data=data, json=json)

        def github_iterate_releases():
            uri_or_url = f"/repos/{GITHUB_REPOSITORY}/releases"
            while True:
                resp = github_req("GET", uri_or_url)
                resp.raise_for_status()
                for release in resp.json():
                    yield release
                if "link" in resp.headers:
                    for i in resp.headers["link"].split(","):
                        link = i.strip()

                        if 'rel="next"' in link:
                            break

                    if 'rel="next"' in link:
                        uri_or_url = re.match(r'<(https://api.github.com/.+)>', link).group(1)
                        continue

                return

        print("Reading OTA information")
        dd = DownloadDescriptor(dd_url)

        assert ota_name.endswith(dd.name.replace(".dd", ""))
        ota_url = dd.object_uri
        ota_payload_properties_url = dd.abdd

        # TargetVersion is not reliable at the moment
        # see https://web.archive.org/web/20251231102756id_/https://dleu.ztems.com/zxmdmp/download.do?doWhat=getDD&filename=firmwarepackages/DE/ZTE/NX769J/432594/GEN_EEA_NX769SV2.0.0B07_TO_GEN_EEA_NX769SV2.0.0B06MR1_CDN.dd
        #target_version = re.search(r"<TargetVersion>(.*)</TargetVersion>", dd.description).group(1)
        release_notes = re.search(r"<ReleaseNotes>(.*)</ReleaseNotes>", dd.description).group(1)

        with session.get(ota_payload_properties_url) as resp:
            resp.raise_for_status()
            ota_payload_properties = load_props(resp.content)

        ota_hashers = {
            "sha256": hashlib.sha256()
        }

        print("Downloading OTA package")
        with tempfile.TemporaryFile() as temp_file:
            fixed_ota_url = re.sub(r'http[s]?://(.+?)(:80|:443)?/(.+)', r'https://\1/\3', ota_url)
            with session.get(fixed_ota_url, stream=True) as resp:
                resp.raise_for_status()
                total_size = int(resp.headers["content-length"])

                last_timestamp = time.time()
                last_offset = 0
                for chunk in resp.iter_content(10245760):
                    temp_file.write(chunk)
                    for hasher in ota_hashers.values():
                        hasher.update(chunk)

                    if time.time() - last_timestamp > 10:
                        progress(temp_file.tell(), total_size, (temp_file.tell() - last_offset) / (time.time() - last_timestamp))
                        last_timestamp = time.time()
                        last_offset = temp_file.tell()
                clear_line()

            print("Digests:")
            for alg, hasher in ota_hashers.items():
                print(f"{alg}:{hasher.hexdigest()}")

            print("Validating OTA package")
            verify_package(temp_file, temp_file.tell(), HttpFile(f"https://github.com/{GITHUB_REPOSITORY}/raw/refs/heads/_certs/otacerts.zip"))

            temp_file.seek(0)

            with ZipFile(temp_file, "r") as ota_file:
                payload_hasher = hashlib.sha256()
                with ota_file.open("payload.bin", "r") as payload_file:
                    while True:
                        chunk = payload_file.read(4096)
                        if chunk:
                            payload_hasher.update(chunk)
                        else:
                            break
                    assert payload_file.tell() == int(ota_payload_properties["FILE_SIZE"])
                    assert payload_hasher.digest() == b64decode(ota_payload_properties["FILE_HASH"])

                package_build_prop = load_props(ota_file.read("build.prop"))
                #assert package_build_prop["ro.build.display.id"] == target_version
                sw_internal_version = package_build_prop["ro.build.sw_internal_version"]

                with session.get(
                    f"https://github.com/{GITHUB_REPOSITORY}/raw/{sw_internal_version}/build.prop",
                    headers=GITHUBUSERCONTENT_HTTP_HEADERS
                ) as resp:
                    if resp.status_code == 403:
                        print(resp.text)
                    resp.raise_for_status()
                    repo_build_prop = load_props(resp.content)
                    assert package_build_prop == repo_build_prop, "build.prop mismatch"

                package_metadata = load_props(ota_file.read("META-INF/com/android/metadata"))
                assert package_metadata["post-build"] == package_build_prop["ro.system.build.fingerprint"]
                with session.get(
                    f"https://github.com/{GITHUB_REPOSITORY}/raw/{ota_name.split('_TO_')[0]}/build.prop",
                    headers=GITHUBUSERCONTENT_HTTP_HEADERS
                ) as resp:
                    if resp.status_code != 404:
                        if resp.status_code == 403:
                            print(resp.text)
                        resp.raise_for_status()
                        source_build_prop = load_props(resp.text)
                        if package_metadata["pre-build"] != source_build_prop["ro.system.build.fingerprint"]:
                            warnings.warn("source build fingerprint mismatch")

                print("Publishing/updating release notes")

                is_downgrade = package_metadata.get("ota-downgrade", None) == "yes"
                if is_downgrade:
                    assert int(ota_payload_properties.get("POWERWASH", "0")) == 1

                github_release = None
                for release in github_iterate_releases():
                    if release["tag_name"] == sw_internal_version:
                        github_release = release

                if github_release is None:
                    github_release_notes = f"📅 {package_build_prop['ro.build.date']}"

                    if IS_REDMAGIC:
                        full_ota_url = redmagic_probe_full_ota_url(DEVICE_MODELS, package_build_prop["ro.build.display.id"], package_build_prop["ro.build.sw_internal_version"])
                        if full_ota_url is not None:
                            github_release_notes += f"\n{full_ota_url}"
                else:
                    github_release_notes = github_release["body"].strip()

                package_release_notes = "<details>"
                package_release_notes += f'<summary><a href="{html.escape(ota_url)}"><code>{html.escape(ota_name)}</code></a>{"⚠️" if is_downgrade else ""}</summary>'
                package_release_notes += release_notes
                package_release_notes += "</details>"

                if package_release_notes in github_release_notes:
                    print("Release notes already uploaded")
                elif ota_name in github_release_notes:
                    raise NotImplementedError
                else:
                    # TODO: try to fetch in other languages (e.g. _ja_jp.dd, _it_it.dd)
                    github_release_notes += "\n\n"
                    github_release_notes += package_release_notes

                release_json = {
                    "tag_name": sw_internal_version,
                    "name": package_build_prop["ro.build.display.id"],
                    "body": github_release_notes.strip(),
                    "draft": True if github_release is None else github_release["draft"],
                    "make_latest": "false"
                }
                if github_release is None:
                    resp = github_req("POST", f"/repos/{GITHUB_REPOSITORY}/releases", json=release_json)
                    resp.raise_for_status()
                    github_release = resp.json()
                elif github_release["body"].strip() != github_release_notes.strip():
                    resp = github_req("PATCH", f'/repos/{GITHUB_REPOSITORY}/releases/{github_release["id"]}', json=release_json)
                    resp.raise_for_status()
                    github_release = resp.json()

            print("Uploading OTA package")

            temp_file.seek(0)
            asset_name = ota_url.split("/")[-1]
            uploaded_assets = [asset["name"] for asset in github_release["assets"]]
            if asset_name in uploaded_assets:
                print("OTA package already uploaded")
            else:
                resp = github_req("POST", github_release["upload_url"].replace("{?name,label}", f"?name={asset_name}"), headers={"Content-Type": "application/zip"}, data=temp_file)
                resp.raise_for_status()
                digest = resp.json()["digest"]
                digest_alg, digest_value = digest.split(":")
                assert ota_hashers[digest_alg].hexdigest() == digest_value

def main():
    url = sys.argv[1]
    if len(sys.argv) > 2:
        repo_folder = sys.argv[2]
    else:
        repo_folder = None

    match_result = re.match(
        rf'(http[s]?://dl.+?\.ztems\.com)(:80|:443)?/zxmdmp/download.do\?doWhat=(getUp|getDD)&filename=(/)?firmwarepackages/(.+)/ZTE/{DEVICE_MODELS[0]}/(\d+)/(.+?)\.(dd|up)',
        url
    )
    assert match_result is not None, "Malformed or unsupported URL"
    
    ota_server = match_result.group(1)
    ota_server_port = match_result.group(2)
    if ota_server_port is None: ota_server_port = ""
    ota_region = match_result.group(5)
    ota_id = match_result.group(6)
    ota_name = match_result.group(7).replace("_CDN", "")

    ota_url = f"{ota_server}{ota_server_port}/zxmdmp/download.do?doWhat=getUp&filename=/firmwarepackages/{ota_region}/ZTE/{DEVICE_MODELS[0]}/{ota_id}/{ota_name}.up"
    dd_url = f"{ota_server}{ota_server_port}/zxmdmp/download.do?doWhat=getDD&filename=/firmwarepackages/{ota_region}/ZTE/{DEVICE_MODELS[0]}/{ota_id}/{ota_name}_CDN.dd"

    if repo_folder is None:
        print("Git repository folder not specified, skipping repository update")
    else:
        update_tracking_repository(repo_folder, ota_url)

    add_package_to_github_release(ota_name, dd_url)

if __name__ == "__main__":
    main()
