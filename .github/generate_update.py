import urllib.request
import re
from datetime import datetime, timezone
from dateutil import parser
import json
import tempfile
import pefile
from collections import OrderedDict

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
    "ios": ("ios", "ios")
}

# File extensions
extensions = {
    "windows": ".exe",
    "macos": ".dmg",
    "android": ".apk",
    "ios": ".ipa"
}

def fetch_html(url):
    """Download and return HTML content from directory listing."""
    with urllib.request.urlopen(url) as response:
        return response.read().decode("utf-8")

def extract_file_and_date(html, ext, system="", variant="", url=""):
    """Extract the most recent file based on the date column."""
    rows = re.findall(
        r'<tr><td><a href="([^"]+%s)".*?</a></td><td[^>]*>\s*\d+\s*</td><td[^>]*>([^<]+)</td>' % re.escape(ext),
        html,
        flags=re.IGNORECASE
    )
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
    print(f"✅ Found newest file for {system}/{variant} → {filename}")
    return filename, date_str

def get_file_version_from_exe_url(url):
    """Extract FileVersion from PE header in EXE."""
    try:
        with urllib.request.urlopen(url) as response:
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
    base_url = f"https://builds.vcmi.download/branch/{channel}"
    channel_obj = make_empty_channel()
    found_any = False  # track if we found at least one artifact

    # Try to set metadata from Windows x64 (anchor build)
    win_url = f"{base_url}/windows-x64/"
    try:
        html = fetch_html(win_url)
    except Exception as e:
        html = ""
    filename, date_str = extract_file_and_date(html, ".exe", "windows", "x64", win_url)

    if filename and date_str:
        # we have our anchor → set metadata
        build_hash_match = re.search(r'VCMI-branch-[\w\-]+-([a-fA-F0-9]+)\.exe', filename)
        if build_hash_match:
            build_hash = build_hash_match.group(1)
        else:
            build_hash = ""

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
        
        # Set the anchor platform download here to avoid re-fetching and duplicate logs
        channel_obj["download"]["windows-x64"] = exe_url

        # Record that we found at least something
        found_any = True
        # also record the windows-x64 download below in the general loop

    # Try to find files for all platforms (fills downloads, independent of metadata)
    for folder_name, (system, variant) in platform_dirs.items():
        # We already processed windows-x64 as the anchor; skip to avoid duplicate log lines
        if folder_name == "windows-x64":
            continue
    
        url = f"{base_url}/{folder_name}/"
        try:
            html = fetch_html(url)
        except Exception:
            continue
    
        # Use a different name to avoid shadowing the outer 'filename'
        fname, _ = extract_file_and_date(html, extensions[system], system, variant, url)
        if not fname:
            continue
    
        download_url = url + fname
        key = f"{system}-{variant}"
        channel_obj["download"][key] = download_url

    # If nothing at all was found for this channel, keep everything empty
    # (channel_obj already initialized as empty)
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
    with urllib.request.urlopen("https://api.github.com/repos/vcmi/vcmi/releases/latest") as response:
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
            "arm64" : "VCMI-Windows-arm64.exe"
        },
        "macos": {
            "arm": "VCMI-macOS-arm.dmg",
            "intel": "VCMI-macOS-intel.dmg"
        },
        "android": {
            "armeabi-v7a": "VCMI-Android-armeabi-v7a.apk",
            "arm64-v8a": "VCMI-Android-arm64-v8a.apk",
            "x86_64": "VCMI-Android-x86_64.apk",
            #"x86": "VCMI-Android-x86.apk",
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
