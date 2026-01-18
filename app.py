from flask import Flask, request, jsonify
from openai import OpenAI
import os
import requests
from bs4 import BeautifulSoup
from datetime import datetime

app = Flask(__name__)

# OpenAI – nøkkel hentes fra Render
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# -------------------------
# KONFIG: BRAND
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
            "academy": "https://adamogeva.no/akademiet/",
            "school": "https://adamogeva.no/skolen/",
            "contact": "https://adamogeva.no/kontakt-oss/"
        }
    }
}

DEFAULT_BRAND = "adam_og_eva"

# -------------------------
# HJELPEFUNKSJONER
# -------------------------

def scrape_page_text(url: str) -> str:
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except Exception:
        return ""

    soup = BeautifulSoup(response.text, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()

    text = soup.get_text(separator="\n")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    cleaned_text = "\n".join(lines)

    return cleaned_text[:8000]


def classify_intent(question: str, brand_name: str) -> str:
    system_prompt = f"""
Du er en intensjonsklassifiserer for chatboten til {brand_name}.
Svar kun med én etikett:

price
booking
salon_info
academy
school
contact
general
"""

    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": question}
        ]
    )

    label = resp.choices[0].message.content.strip().lower()
    if label not in CONFIG[DEFAULT_BRAND]["intents"]:
        label = "general"
    return label


def build_answer_from_scrape(question: str, brand_conf: dict, intent: str) -> dict:
    url = brand_conf["intents"].get(intent, brand_conf["base_url"])
    scraped_text = scrape_page_text(url)

    # Spesialregler – kun når relevant
    extra_facts = ""

    if intent == "school":
        extra_facts = f"""
VIKTIG EKSTRA INFORMASJON:
- Frisørutdanningen koster {SCHOOL_PRICE}
- Skolen er støttet av Lånekassen
- Lenke til Lånekassen: {LANEKASSEN_URL}
"""

    system_prompt = f"""
Du er kundeservice-chatbot for {brand_conf["name"]}.
Du skal ALLTID svare på norsk.

REGLER (MÅ FØLGES):
- Bruk KUN informasjon som finnes i teksten nedenfor.
- Ikke spekuler, ikke forklar, ikke utvid.
- Hvis svaret ikke finnes: si at du ikke fant informasjon.
- Inkluder ALLTID lenke til aktuell side når du svarer.
- Ikke vis salonglenker med mindre bruker spør om salong.
- Skill mellom elev (Akademiet) og lærling (salong).

{extra_facts}

NETTSIDETEKST (fra {url}):
{scraped_text}
"""

    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": question}
        ]
    )

    answer = resp.choices[0].message.content.strip()

    return {
        "answer": answer,
        "references": [url] + ([LANEKASSEN_URL] if intent == "school" else [])
    }


# -------------------------
# FLASK-RUTER
# -------------------------

@app.route("/fetch-answer", methods=["POST"])
def fetch_answer():
    data = request.json or {}

    brand_key = data.get("brand") or DEFAULT_BRAND
    brand_conf = CONFIG.get(brand_key, CONFIG[DEFAULT_BRAND])

    question = (
        data.get("user_input")
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
    result = build_answer_from_scrape(question, brand_conf, intent)

    # Logging (kan byttes til DB)
    print({
        "timestamp": datetime.utcnow().isoformat(),
        "question": question,
        "intent": intent,
        "references": result["references"]
    })

    return jsonify(result)


@app.route("/", methods=["GET"])
def home():
    return "Adam og Eva chatbot-backend kjører."


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
