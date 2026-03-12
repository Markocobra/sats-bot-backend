import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

BASE_URL = "https://adamogeva.no"

visited = set()
pages = []


def crawl(url):

    if url in visited:
        return

    if BASE_URL not in url:
        return

    print("Crawler:", url)

    visited.add(url)

    try:
        r = requests.get(url, timeout=10)
    except:
        return

    soup = BeautifulSoup(r.text, "html.parser")

    text = soup.get_text(" ", strip=True)

    pages.append({
        "url": url,
        "text": text
    })

    for link in soup.find_all("a", href=True):

        next_url = urljoin(BASE_URL, link["href"])

        if urlparse(next_url).netloc == urlparse(BASE_URL).netloc:
            crawl(next_url)


crawl(BASE_URL)

print("Antall sider:", len(pages))

import json

with open("website_data.json", "w", encoding="utf-8") as f:
    json.dump(pages, f, ensure_ascii=False, indent=2)

print("Data lagret til website_data.json")