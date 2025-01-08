import os
import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

def fetch_url(url):
    """Fetch the URL content with retries."""
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retries))
    response = session.get(url, timeout=10)
    response.raise_for_status()
    return response

def extract_versions(soup, stable_label, mainline_label, prefix):
    """Extract stable and mainline versions based on labels and prefix."""
    versions = {"stable": None, "mainline": None}
    for tag in soup.find_all(["strong", "h4"]):
        text = tag.get_text(strip=True).lower()
        if stable_label in text:
            table_or_next = tag.find_next(["a", "table"])
            if table_or_next:
                version_link = table_or_next.find("a", href=True, string=lambda s: s and prefix in s)
                if version_link:
                    versions["stable"] = version_link.string.split('-')[1].strip('.tar.gz')
        elif mainline_label in text:
            table_or_next = tag.find_next(["a", "table"])
            if table_or_next:
                version_link = table_or_next.find("a", href=True, string=lambda s: s and prefix in s)
                if version_link:
                    versions["mainline"] = version_link.string.split('-')[1].strip('.tar.gz')
    return versions

def get_nginx_versions():
    url = "https://nginx.org/en/download.html"
    try:
        print(f"Fetching {url}...")
        response = fetch_url(url)
    except requests.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return {"stable": None, "mainline": None}

    soup = BeautifulSoup(response.text, 'html.parser')
    return extract_versions(soup, "stable version", "mainline version", "nginx-")

def get_freenginx_versions():
    url = "https://freenginx.org/en/download.html"
    try:
        print(f"Fetching {url}...")
        response = fetch_url(url)
    except requests.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return {"stable": None, "mainline": None}

    soup = BeautifulSoup(response.text, 'html.parser')
    return extract_versions(soup, "stable version", "mainline version", "freenginx-")

def main():
    print("Fetching Nginx versions...")
    nginx_versions = get_nginx_versions()

    print("Fetching FreeNginx versions...")
    freenginx_versions = get_freenginx_versions()

    # Create output in GitHub Actions matrix format
    versions = []
    if nginx_versions['stable']:
        versions.append(f"nginx-{nginx_versions['stable']}")
    if nginx_versions['mainline']:
        versions.append(f"nginx-{nginx_versions['mainline']}")
    if freenginx_versions['stable']:
        versions.append(f"freenginx-{freenginx_versions['stable']}")
    if freenginx_versions['mainline']:
        versions.append(f"freenginx-{freenginx_versions['mainline']}")

    # Output for GitHub Actions
    print(f"::set-output name=matrix::{versions}")

    # Save detailed results to a file
    output_file = os.getenv("VERSION_OUTPUT", "versions.txt")
    with open(output_file, "w") as f:
        f.write("Latest Versions:\n")
        f.write(f"Nginx Stable: {nginx_versions['stable']}\n")
        f.write(f"Nginx Mainline: {nginx_versions['mainline']}\n")
        f.write(f"FreeNginx Stable: {freenginx_versions['stable']}\n")
        f.write(f"FreeNginx Mainline: {freenginx_versions['mainline']}\n")

if __name__ == "__main__":
    main()