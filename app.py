    from flask import Flask, request, jsonify
from openai import OpenAI
import os
import requests
from bs4 import BeautifulSoup

app = Flask(__name__)

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# -------------------------
# KONFIG: KUNDER / BRANDS
# -------------------------

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
    """
    Henter og renser tekst fra en nettside.
    """
    try:
        print(f"🌐 Henter URL: {url}")
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except Exception as e:
        print("❌ Klarte ikke å hente URL:", url, e)
        return ""

    soup = BeautifulSoup(response.text, "html.parser")

    # Fjern støy
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()

    text = soup.get_text(separator="\n")
    lines = [line.strip() for line in text.splitlines()]
    lines = [line for line in lines if line]

    cleaned_text = "\n".join(lines)

    max_chars = 8000
    if len(cleaned_text) > max_chars:
        cleaned_text = cleaned_text[:max_chars]

    print(f"📄 Lengde på skrapet tekst: {len(cleaned_text)}")
    return cleaned_text


def classify_intent(question: str, brand_name: str) -> str:
    """
    Bruker en liten OpenAI-modell til å finne intensjon.
    Returnerer én av:
    - price
    - booking
    - salon_info
    - academy
    - school
    - contact
    - general
    """
    system_prompt = f"""
Du er en intensjonsklassifiserer for en chatbot for {brand_name}.
Du skal kun svare med én av disse etikettene (ingenting annet):

- price
- booking
- salon_info
- academy
- school
- contact
- general

price: når brukeren spør om priser, kostnad, hva noe koster, prisliste, behandlinger.
booking: når brukeren spør om å bestille time, booke, avbestille, endre time.
salon_info: når brukeren spør om spesifikk salong, adresse, telefonnummer, åpningstider, lokasjon.
academy: når brukeren spør om kurs, akademi, opplæring for frisører.
school: når brukeren spør om frisørskole, utdanning, skole.
contact: når brukeren spør om kontakt, kundeservice, e-post, generelle henvendelser.
general: alt annet.
"""

    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": question}
        ]
    )

    label = resp.choices[0].message.content.strip().lower()
    print("🎯 Intent klassifisert som:", label)
    # fallback hvis modellen tuller
    if label not in [
        "price", "booking", "salon_info",
        "academy", "school", "contact", "general"
    ]:
        label = "general"
    return label


def build_answer_from_scrape(question: str, brand_conf: dict, intent: str) -> str:
    """
    Scraper riktig URL basert på intent og lar OpenAI svare kun basert på den teksten.
    """
    intents_conf = brand_conf.get("intents", {})
    url = intents_conf.get(intent)

    # Hvis vi ikke har en spesifikk URL for denne intensjonen, bruk base_url
    if not url:
        url = brand_conf.get("base_url")

    scraped_text = scrape_page_text(url)

    system_prompt = f"""
Du er en hjelpsom chatbot for {brand_conf.get("name")}.
Svar alltid på norsk.
Svar hyggelig og profesjonelt.
Du skal svare KUN basert på teksten under. Ikke gjett.
Hvis du ikke finner svaret, si at du ikke finner det i informasjonen du har.

NETTSIDETEKST (fra {url}):

{scraped_text}

Når det er naturlig, legg ved lenken {url} i svaret ditt.
"""

    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": question}
        ]
    )

    answer = resp.choices[0].message.content.strip()
    return answer

# -------------------------
# FLASK-RUTER
# -------------------------

@app.route("/fetch-answer", methods=["POST"])
def fetch_answer():
    data = request.json or {}

    # Hvilken brand? (kan komme fra Landbot senere)
    brand_key = data.get("brand") or DEFAULT_BRAND
    brand_conf = CONFIG.get(brand_key, CONFIG[DEFAULT_BRAND])

    # Hent spørsmål
    question = (
        data.get("user_input")
        or data.get("message")
        or data.get("text")
        or data.get("question")
        or ""
    )

    print("🔍 Spørsmål mottatt:", question)
    print("🏷️ Brand:", brand_key)

    if not question:
        return jsonify({"answer": "Jeg mottok ikke noe spørsmål."})

    # 1) Finn intensjon
    intent = classify_intent(question, brand_conf.get("name"))

    # 2) Bygg svar basert på scraping + intent
    answer = build_answer_from_scrape(question, brand_conf, intent)

    return jsonify({"answer": answer})


@app.route("/", methods=["GET"])
def home():
    return "Multibrand chatbot-backend kjører."


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)

