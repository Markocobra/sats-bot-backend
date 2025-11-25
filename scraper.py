import requests
from bs4 import BeautifulSoup
from cachetools import TTLCache, cached

cache = TTLCache(maxsize=100, ttl=300)

API_URL = "https://www.sats.no/treningssenter/akersgata/"

@cached(cache)
def fetch_info():
    r = requests.get(API_URL, timeout=10)
    r.raise_for_status()
    return r.text   # <-- VI HENTER HTML, IKKE JSON!

def fetch_information_for_question(question: str):
    question = question.lower()

    html = fetch_info()
    soup = BeautifulSoup(html, "html.parser")

    # Finn åpningstid-seksjonen
    hours_box = soup.find("div", {"class": "opening-hours"})

    if not hours_box:
        return "Fant ikke åpningstider."

    rows = hours_box.find_all("div", class_="opening-hours-day")

    formatted = []
    for row in rows:
        day = row.find("span", class_="day").text.strip()
        hours = row.find("span", class_="hours").text.strip()
        formatted.append(f"{day}: {hours}")

    return "\n".join(formatted)
