import urllib.request
import urllib.error
import re
from datetime import datetime, timezone
from dateutil import parser
import json
import tempfile
import pefile
from collections import OrderedDict

DEBUG = True

def debug_print(msg):
    if DEBUG:
        print(msg)

# Folder name → (system, variant)
platform_dirs = {
    "windows-x64": ("windows", "x64"),
    "windows-x86": ("windows", "x86"),
    "windows-arm64": ("windows", "arm64"),
    "macos-intel": ("macos", "intel"),
    "macos-arm": ("macos", "arm"),
    "android-armeabi-v7a": ("android", "armeabi-v7a"),
    "android-arm64-v8a": ("android", "arm64-v8a"),
    "android-x64": ("android", "x86_64"),
    # "android-x86": ("android", "x86"),
    "linux-x86_64": ("linux", "x86_64"),
    "linux-arm64": ("linux", "arm64"),
    "ios": ("ios", "ios")
}

# File extensions
extensions = {
    "windows": ".exe",
    "macos": ".dmg",
    "android": ".apk",
    "linux": ".AppImage",
    "ios": ".ipa"
}

def fetch_html(url):
    """Download and return HTML content from directory listing."""
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/122.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
    )

    try:
        with urllib.request.urlopen(req) as response:
            status = getattr(response, "status", 200)
            data = response.read()
            debug_print(f"🌐 {url} -> HTTP {status}, {len(data)} bytes")
            return data.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        debug_print(f"❌ {url} -> HTTPError {e.code}")
        raise
    except urllib.error.URLError as e:
        debug_print(f"❌ {url} -> URLError {e}")
        raise

def extract_file_and_date(html, ext, system="", variant="", url=""):
    """Extract the most recent file based on the date column."""
    pattern = (
        r'<tr><td><a href="([^"]+%s)".*?</a></td>'
        r'<td[^>]*>\s*\d+\s*</td><td[^>]*>([^<]+)</td>'
    ) % re.escape(ext)

    rows = re.findall(
        pattern,
        html,
        flags=re.IGNORECASE
    )

    if DEBUG:
        debug_print(f"🔎 regex rows for {system}/{variant} ({ext}) at {url}: {len(rows)}")
        if not rows:
            sample_lines = []
            for line in html.splitlines():
                if ext.lower() in line.lower():
                    sample_lines.append(line.strip())
                    if len(sample_lines) >= 3:
                        break
            if sample_lines:
                debug_print("🧩 sample lines containing extension:")
                for s in sample_lines:
                    debug_print("   " + s[:200])
            else:
                debug_print("🧩 no lines containing extension found (maybe blocked page / different content)")

    if not rows:
        print(f"❌ No match for {system}/{variant} at {url}")
        return None, None

    def parse_date(date_str):
        try:
            return datetime.strptime(date_str, "%Y-%b-%d %H:%M")
        except ValueError:
            return datetime.min

    rows.sort(key=lambda x: parse_date(x[1]), reverse=True)
    filename, date_str = rows[0]
    print(f"✅ Found newest file for {system}/{variant} → {filename} ({date_str})")
    return filename, date_str

def get_file_version_from_exe_url(url):
    """Extract FileVersion from PE header in EXE."""
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                              "(KHTML, like Gecko) Chrome/122.0 Safari/537.36"
            }
        )
        with urllib.request.urlopen(req) as response:
            with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                tmp_file.write(response.read())
                tmp_path = tmp_file.name

        pe = pefile.PE(tmp_path)
        for fileinfo in pe.FileInfo:
            for entry in fileinfo:
                if hasattr(entry, 'StringTable'):
                    for st in entry.StringTable:
                        version = st.entries.get(b"FileVersion") or st.entries.get("FileVersion")
                        if version:
                            version = version.decode("utf-8") if isinstance(version, bytes) else version
                            return version.replace(" ", "").strip()
    except Exception as e:
        print(f"⚠️ Could not extract version from EXE: {e}")
    return "1.6.8"

# Create default download key map
empty_download_map = OrderedDict(
    (f"{system}-{variant}", "") for _, (system, variant) in platform_dirs.items()
)

def make_empty_channel():
    # Use the global empty_download_map prepared above
    ch = OrderedDict()
    ch["version"] = ""
    ch["commit"] = ""
    ch["buildDate"] = ""
    ch["changeLog"] = ""
    ch["download"] = OrderedDict(empty_download_map)
    return ch

# Process nightly branches
channels = ["develop", "beta"]
channel_results = {}

for channel in channels:
    print(f"\n===== {channel} =====")
    base_url = f"https://builds.vcmi.download/branch/{channel}"
    channel_obj = make_empty_channel()
    found_any = False  # track if we found at least one artifact

    # Try to set metadata from Windows x64 (anchor build)
    win_url = f"{base_url}/windows-x64/"
    try:
        html = fetch_html(win_url)
    except Exception as e:
        print(f"⚠️ Anchor fetch failed: {win_url} -> {e}")
        html = ""

    filename, date_str = extract_file_and_date(html, ".exe", "windows", "x64", win_url)

    if filename and date_str:
        build_hash_match = re.search(r'VCMI-branch-[\w\-]+-([a-fA-F0-9]+)\.exe', filename)
        build_hash = build_hash_match.group(1) if build_hash_match else ""

        build_date = ""
        try:
            build_date = datetime.strptime(date_str, "%Y-%b-%d %H:%M").strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            pass

        exe_url = f"{win_url}{filename}"
        version_string = get_file_version_from_exe_url(exe_url) or ""

        channel_obj["version"] = version_string
        channel_obj["commit"] = build_hash
        channel_obj["buildDate"] = build_date
        channel_obj["changeLog"] = f"Latest nightly build from {channel} branch."
        channel_obj["download"]["windows-x64"] = exe_url

    # Try to find files for all platforms
    for folder_name, (system, variant) in platform_dirs.items():
        if folder_name == "windows-x64":
            continue

        url = f"{base_url}/{folder_name}/"
        try:
            html = fetch_html(url)
        except Exception as e:
            print(f"⚠️ Fetch failed: {url} -> {e}")
            continue

        fname, _ = extract_file_and_date(html, extensions[system], system, variant, url)
        if not fname:
            continue

        download_url = url + fname
        key = f"{system}-{variant}"
        channel_obj["download"][key] = download_url

    channel_results[channel] = channel_obj

# Write develop and beta JSON
for channel, data in channel_results.items():
    filename = f"vcmi-{channel}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"📄 Written {filename}")

# Stable channel from GitHub releases
print("\n🔍 Fetching stable release from GitHub...")
try:
    req = urllib.request.Request(
        "https://api.github.com/repos/vcmi/vcmi/releases/latest",
        headers={"User-Agent": "vcmi-update-script/1.0"}
    )
    with urllib.request.urlopen(req) as response:
        release = json.load(response)

    stable_obj = OrderedDict()
    stable_obj["version"] = release["tag_name"]
    stable_obj["buildDate"] = parser.isoparse(release["published_at"]).strftime("%Y-%m-%d %H:%M:%S")
    stable_obj["changeLog"] = release.get("body", "Latest stable release.")
    stable_obj["download"] = OrderedDict(empty_download_map)

    stable_mapping = {
        "windows": {
            "x64": "VCMI-Windows-x64.exe",
            "x86": "VCMI-Windows-x86.exe",
            "arm64": "VCMI-Windows-arm64.exe"
        },
        "macos": {
            "arm": "VCMI-macOS-arm.dmg",
            "intel": "VCMI-macOS-intel.dmg"
        },
        "android": {
            "armeabi-v7a": "VCMI-Android-armeabi-v7a.apk",
            "arm64-v8a": "VCMI-Android-arm64-v8a.apk",
            "x86_64": "VCMI-Android-x86_64.apk",
        },
        "linux": {
            "x86_64": "VCMI-Linux-x86_64.AppImage",
            "arm64": "VCMI-Linux-arm64.AppImage",
        },
        "ios": {
            "ios": "VCMI-iOS.ipa"
        }
    }

    for system, variants in stable_mapping.items():
        for variant, filename in variants.items():
            key = f"{system}-{variant}"
            asset = next((a for a in release.get("assets", []) if a["name"] == filename), None)
            if asset:
                print(f"✅ Found stable {key}: {filename}")
                stable_obj["download"][key] = asset["browser_download_url"]
            else:
                print(f"❌ Missing stable {key}: {filename}")

    with open("vcmi-stable.json", "w", encoding="utf-8") as f:
        json.dump(stable_obj, f, indent=2, ensure_ascii=False)
    print("📄 Written vcmi-stable.json")

except Exception as e:
    print(f"⚠️ Failed to fetch stable release: {e}")
