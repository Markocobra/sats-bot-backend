from flask import Flask, request, jsonify
from openai import OpenAI
from dotenv import load_dotenv

import os
import requests
from bs4 import BeautifulSoup
from datetime import datetime

# -------------------------
# LOAD ENV (.env)
# -------------------------
load_dotenv()

# -------------------------
# APP & OPENAI
# -------------------------
app = Flask(__name__)

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# -------------------------
# KONFIG
# -------------------------
LANEKASSEN_URL = "https://lanekassen.no/nb-NO/"
SCHOOL_PRICE = "89 000 kr"

CONFIG = {
    "adam_og_eva": {
        "name": "Adam og Eva",
        "base_url": "https://adamogeva.no",
        "intents": {
            "price": "https://adamogeva.no/prisliste/",
            "booking": "https://adamogeva.no/bestill-time/",
            "salon_info": "https://adamogeva.no/salonger/",
            "academy": "https://akademiet.adamogeva.no/",
            "school": "https://akademiet.adamogeva.no/",
            "apprenticeship": "https://adamogeva.no/salonger/",
            "contact": "https://adamogeva.no/kontakt-oss/",
        },
    }
}

DEFAULT_BRAND = "adam_og_eva"

# -------------------------
# HJELPEFUNKSJONER
# -------------------------
def scrape_page_text(url: str) -> str:
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
    except Exception:
        return ""

    soup = BeautifulSoup(r.text, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()

    text = soup.get_text(separator="\n")
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    return "\n".join(lines)[:8000]


def fetch_from_wp_api(intent: str) -> tuple[str, str]:
    """
    Forsøker å hente tekst fra WordPress REST API.
    Returnerer (tekst, kilde_url) eller ("", "")
    """
    try:
        if intent in ["school", "academy"]:
            search = "akademi skole utdanning"
        elif intent in ["salon_info", "apprenticeship"]:
            search = "salong"
        elif intent == "price":
            search = "pris prisliste"
        else:
            return "", ""

        url = (
            "https://adamogeva.no/wp-json/wp/v2/pages"
            f"?search={search}&per_page=3"
        )

        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        pages = resp.json()

        if not pages:
            return "", ""

        texts = []
        source_url = pages[0].get("link", "")

        for page in pages:
            title = page.get("title", {}).get("rendered", "")
            html = page.get("content", {}).get("rendered", "")
            soup = BeautifulSoup(html, "html.parser")
            text = soup.get_text(separator="\n")
            texts.append(f"{title}\n{text}")

        return "\n\n".join(texts)[:8000], source_url

    except Exception:
        return "", ""


def classify_intent(question: str, brand_name: str) -> str:
    system_prompt = f"""
Du er en intensjonsklassifiserer for chatboten til {brand_name}.
Svar KUN med én av disse etikettene:

price
booking
salon_info
academy
school
apprenticeship
contact
general

REGLER:
- LÆRLING / LÆREPLASS → apprenticeship
- ELEV / SKOLE / UTDANNING → school
- AKADEMI / KURS → academy
"""

    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": question},
        ],
    )

    label = resp.choices[0].message.content.strip().lower()

    # bare returner label hvis den finnes i intents
    if label in CONFIG[DEFAULT_BRAND]["intents"]:
        return label

    return "general"


def build_answer(question: str, brand_conf: dict, intent: str) -> dict:
    references = []
    authoritative = ""

    # Autoritative fakta
    if intent == "school":
        authoritative = f"""
AUTORITATIV INFORMASJON:
- Frisørutdanningen hos Adam og Eva koster {SCHOOL_PRICE}
- Skolen er støttet av Lånekassen
- {LANEKASSEN_URL}
"""
        references.append(LANEKASSEN_URL)

    # 1) Prøv REST API
    api_text, api_source = fetch_from_wp_api(intent)

    if api_text:
        content = api_text
        source_type = "REST API"
        if api_source:
            references.append(api_source)
    else:
        # 2) Fallback: scraping
        url = brand_conf["intents"].get(intent, brand_conf["base_url"])
        content = scrape_page_text(url)
        source_type = "SCRAPING"
        references.append(url)

    system_prompt = f"""
Du er kundeservice-chatbot for {brand_conf["name"]}.
Svar alltid på norsk.

REGLER:
- Bruk kun informasjon fra:
  1) Autoritative fakta
  2) {source_type}
- Ikke spekuler.
- Ikke bland elev og lærling.
- Ikke gi salonglenker uten at bruker spør om salong.

{authoritative}

INNHOLD:
{content}
"""

    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": question},
        ],
    )

    return {
        "answer": resp.choices[0].message.content.strip(),
        "references": list(set(references)),
    }


# -------------------------
# ROUTES
# -------------------------
@app.route("/fetch-answer", methods=["POST"])
def fetch_answer():
    data = request.json or {}

    brand_key = data.get("brand") or DEFAULT_BRAND
    brand_conf = CONFIG.get(brand_key, CONFIG[DEFAULT_BRAND])

    question = (
        data.get("user_input")   # Landbot
        or data.get("message")
        or data.get("text")
        or data.get("question")
        or ""
    ).strip()

    if not question:
        return jsonify({
            "answer": "Hei, og velkommen til Adam og Eva kundeservice-chatbot! Still meg et spørsmål, så svarer jeg deg."
        })

    intent = classify_intent(question, brand_conf["name"])
    result = build_answer(question, brand_conf, intent)

    print({
        "timestamp": datetime.utcnow().isoformat(),
        "question": question,
        "intent": intent,
        "references": result["references"],
    })

    return jsonify(result)


@app.route("/", methods=["GET"])
def home():
    return "Adam og Eva chatbot-backend kjører."


# -------------------------
# RUN SERVER
# -------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
