import argparse
import datetime
import json
import os
from os.path import abspath, basename, dirname
from passlib.hash import bcrypt_sha256
import secrets
from yaml import load
import zipfile

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

from pkgroot import PACKAGE_ROOT

def main():
    challenges = []
    dynamic_challenge = []
    flags = []
    tags = []
    hints = []
    files = []
    pages = []
    users = []

    files_source = {} # {original_location: archive_location}
    files_template = {} # {template_varname: href_path}

    ####################
    # arguments
    ####################
    parser = argparse.ArgumentParser(
                    prog='ctfarchive',
                    description='Create ctfd archive')
    
    parser.add_argument('-c', '--config', required=True) # config.yaml
    parser.add_argument('-o', '--output', default="archive_zipfile.zip")
    args = parser.parse_args()

    config_dir = dirname(abspath(args.config))
    with open(args.config) as f:
        config = load(f, Loader=Loader)

    source = [] # ("Web", "challenge_web.yaml")
    for challenge in config["challenges"]:
        source.append((challenge["category"], f"{config_dir}/{challenge['source']}"))

    #######################
    # config.yaml
    #######################
    # files
    for file in (config["files"] if "files" in config.keys() else []):
        hash = secrets.token_hex(nbytes=16)
        file_id = len(files) + 1
        files.append({
            "id": file_id,
            "type": "challenge",
            "location": f"{hash}/{basename(file['source'])}",
            "challenge_id": None,
            "page_id": None
        })
        files_source[file["source"]] = f"{hash}/{basename(file['source'])}"
        files_template[file["name"]] = f"/files/{hash}/{basename(file['source'])}"

    # pages
    for page in config["pages"]:
        page_id = len(pages) + 1
        pages.append({
            "id": page_id,
            "title": page["title"],
            "route": page["route"],
            "content": page["content"].format(**files_template),
            "draft": page["draft"] if "draft" in page.keys() else 0,
            "hidden": page["hidden"] if "hidden" in page.keys() else 0,
            "auth_required": page["auth_required"] if "auth_required" in page.keys() else 1,
        })

    # users
    for user in config["users"]:
        user_id = len(users) + 1
        users.append({
            "id": user_id,
            "name": user["name"],
            "password": bcrypt_sha256.hash(user["password"]),
            "email": user["email"],
            "type": user["type"],
            "created_at": datetime.datetime.now().isoformat().split(".")[0],
            "oauth_id": None,
            "secret": None,
            "website": None,
            "affiliation": None,
            "country": None,
            "bracket": None,
            "hidden":1,
            "banned":0,
            "verified":1,
            "team_id":None
        })

    #########################
    # challenges yaml
    #########################
    for (category, filename) in source:
        with open(filename) as f:
            data = load(f, Loader=Loader)

        # files
        for file in (data["files"] if "files" in data.keys() else []):
            hash = secrets.token_hex(nbytes=16)
            file_id = len(files) + 1
            files.append({
                "id": file_id,
                "type": "challenge",
                "location": f"{hash}/{basename(file['source'])}",
                "challenge_id": None,
                "page_id": None
            })
            files_source[file["source"]] = f"{hash}/{basename(file['source'])}"
            files_template[file["name"]] = f"/files/{hash}/{basename(file['source'])}"

        # challenges
        for c in data["challenges"]:
            challenge_id = len(challenges) + 1
            challenges.append({
            "id": challenge_id,
            "name": c["name"],
            "description": c["description"].format(**files_template),
            "max_attempts": 0,
            "value": config["dynamic"]["initial"],
            "category": category,
            "type": c["type"] if "type" in c.keys() else (config["defaults"]["type"]),
            "state": "visible",
            "requirements": None,
            "connection_info": c["connection_info"] if "connection_info" in c.keys() else None,
            "next_id": None
            })

            dynamic_challenge.append({
                "id": challenge_id,
                "initial": config["dynamic"]["initial"],
                "minimum": config["dynamic"]["minimum"],
                "decay": config["dynamic"]["decay"],
            })

            # tags
            for tag in (c["tags"] if "tags" in c.keys() else []):
                tag_id = len(tags) + 1
                tags.append({
                    "id": tag_id,
                    "challenge_id": challenge_id,
                    "value": tag
                })

            # hints
            for h in (c["hints"] if "hints" in c.keys() else []):
                hint_id = len(hints) + 1
                hints.append({
                    "id": hint_id,
                    "type": "standard",
                    "challenge_id": challenge_id,
                    "content": h["content"].format(**files_template),
                    "cost": h["cost"],
                    "requirements": None
                })

            # attachments
            for attachment in (c["attachments"] if "attachments" in c.keys() else []):
                hash = secrets.token_hex(nbytes=16)
                file_id = len(files) + 1
                files.append({
                    "id": file_id,
                    "type": "challenge",
                    "location": f"{hash}/{basename(attachment['source'])}",
                    "challenge_id": challenge_id,
                    "page_id": None
                })
                files_source[attachment["source"]] = f"{hash}/{basename(attachment['source'])}"

            flags.append({
                "id": challenge_id,
                "challenge_id": challenge_id,
                "type": "static",
                "content": c["flag"],
                "data": ""
            })


    ####################
    # export archive
    ####################
    with zipfile.ZipFile(args.output, 'w',
                        compression=zipfile.ZIP_DEFLATED,
                        compresslevel=9) as zf:
        zf.writestr("db/challenges.json", json.dumps({
                    "count": len(challenges),
                    "results": challenges,
                    "meta": {}
                }))

        zf.writestr("db/dynamic_challenge.json", json.dumps({
                "count": len(dynamic_challenge),
                "results": dynamic_challenge,
                "meta": {}
            }))

        zf.writestr("db/tags.json", json.dumps({
                "count": len(tags),
                "results": tags,
                "meta": {}
            }))

        zf.writestr("db/hints.json", json.dumps({
                "count": len(hints),
                "results": hints,
                "meta": {}
            }))

        zf.writestr("db/files.json", json.dumps({
                "count": len(files),
                "results": files,
                "meta": {}
            }))

        zf.writestr("db/flags.json", json.dumps({
                "count": len(flags),
                "results": flags,
                "meta": {}
            }))

        zf.writestr("db/pages.json", json.dumps({
                "count": len(pages),
                "results": pages,
                "meta": {}
            }))

        zf.writestr("db/users.json", json.dumps({
                "count": len(users),
                "results": users,
                "meta": {}
            }))
        
        for static_json in os.listdir(f"{PACKAGE_ROOT}/static"):
            zf.write(f"{PACKAGE_ROOT}/static/{static_json}", f"db/{basename(static_json)}")

        for original_location, archive_location in files_source.items():
            zf.write(f"{config_dir}/{original_location}", f"uploads/{archive_location}")

if __name__ == "__main__":
    main()