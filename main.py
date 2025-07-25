#!/usr/bin/env python3
import argparse
import json
import pathlib
import sys
from typing import Final

import requests


def parse_args():
    parser = argparse.ArgumentParser(description="Security scan tool using WhatCMS API")
    parser.add_argument('--target', required=True, help='Target domain or URL')
    parser.add_argument('--apikey', required=True, help='WhatCMS API key')
    parser.add_argument('--output', required=True, help='Output file name for JSON results')
    return parser.parse_args()


def normalize_target(target):
    if target.startswith(('http://', 'https://')):
        return target
    for scheme in ('http://', 'https://'):
        try:
            r = requests.get(scheme + target, timeout=5)
            if r.status_code < 400:
                return scheme + target
        except requests.RequestException:
            continue
    sys.exit("Connection Error")


def get_cms_info(target, apikey):
    url = f"https://whatcms.org/APIEndpoint?key={apikey}&url={target}"
    r = requests.get(url)
    if r.status_code != 200:
        sys.exit("API request failed")
    data = r.json()
    if "msg" in data and "Invalid API key" in data["msg"]:
        return "Invalid API key"
    return {
        "name": data.get("name"),
        "version": data.get("version"),
        "confidence": data.get("confidence")
    }


def check_wordpress(target, version, messages):
    print("Starting WordPress security checks...")
    try:
        r = requests.get(f"{target}/readme.html", timeout=5)
        if r.status_code == 200:
            msg = "readme.html is accessible – version disclosure risk"
            print(msg)
            messages.append(msg)
    except requests.RequestException:
        pass
    try:
        r = requests.get(f"{target}/wp-config.php", timeout=5)
        if r.status_code == 200:
            msg = "wp-config.php is accessible – critical security risk"
            print(msg)
            messages.append(msg)
    except requests.RequestException:
        pass
    if version:
        try:
            wp_api = requests.get("https://api.wordpress.org/core/version-check/1.7/", timeout=5).json()
            latest = wp_api.get("offers", [{}])[0].get("current")
            if latest and version != latest:
                msg = f"WordPress version ({version}) is outdated. Latest: {latest}"
                print(msg)
                messages.append(msg)
        except requests.RequestException:
            pass


def check_joomla(target, messages):
    print("Starting Joomla security checks...")
    try:
        r = requests.get(f"{target}/configuration.php", timeout=5)
        if r.status_code == 200:
            msg = "configuration.php is accessible – sensitive data exposure risk"
            print(msg)
            messages.append(msg)
    except requests.RequestException:
        pass
    try:
        r = requests.get(f"{target}/administrator/", timeout=5)
        if r.status_code == 200:
            msg = "/administrator/ directory is accessible – check access restrictions"
            print(msg)
            messages.append(msg)
    except requests.RequestException:
        pass


def check_drupal(target, messages):
    print("Starting Drupal security checks...")
    try:
        r = requests.get(f"{target}/CHANGELOG.txt", timeout=5)
        if r.status_code == 200:
            msg = "CHANGELOG.txt is accessible – version disclosure risk"
            print(msg)
            messages.append(msg)
    except requests.RequestException:
        pass


def check_security_headers(target, messages):
    print("Checking common security headers...")
    try:
        r = requests.get(target, timeout=5)
        headers = r.headers
        if "Content-Security-Policy" not in headers:
            msg = "Missing Content-Security-Policy header"
            print(msg)
            messages.append(msg)
        if "X-Frame-Options" not in headers:
            msg = "Missing X-Frame-Options header"
            print(msg)
            messages.append(msg)
    except requests.RequestException:
        pass


def run(target, apikey):
    target = normalize_target(target)

    result = {
        "target": target,
        "messages": []
    }

    cms = get_cms_info(target, apikey)

    if cms == "Invalid API key":
        result=  {
            "target": target,
            "messages": [cms]
        }
        return result

    name = cms.get("name")
    version = cms.get("version")
    confidence = cms.get("confidence", 0)

    if name and confidence >= 80:
        combined_cms = f"Detected CMS: {name} {version}" if version else f"Detected CMS: {name}"
        print(combined_cms)
        result["messages"].append(combined_cms)

    if name == "WordPress":
        check_wordpress(target, version, result["messages"])
    elif name == "Joomla":
        check_joomla(target, result["messages"])
    elif name == "Drupal":
        check_drupal(target, result["messages"])

    check_security_headers(target, result["messages"])
    return result


def main():
    args = parse_args()

    target: str = args.target
    apikey: str = args.apikey
    output: str = args.output

    result = run(
        target=target,
        apikey=apikey,
    )

    MAIN_DIR: Final[pathlib.Path] = pathlib.Path(__file__).resolve().parents[0]
    output_path = MAIN_DIR / output

    with output_path.open('w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print(f"RESULTS:\n{json.dumps(result, indent=4)}")
    print(f"Results saved to {output_path}")


if __name__ == "__main__":
    main()
