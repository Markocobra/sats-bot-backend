from flask import Flask, request, jsonify
from openai import OpenAI
import os
import requests
from bs4 import BeautifulSoup

app = Flask(__name__)

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

BASE_SYSTEM_PROMPT = """
Du er en hjelpsom chatbot for frisørkjeden Adam og Eva.
Svar alltid på norsk.
Svar hyggelig og profesjonelt.
Hvis du ikke finner svaret i teksten under, si at du ikke vet – ikke gjett.
"""

def scrape_page_text(url: str) -> str:
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except Exception as e:
        print("❌ Klarte ikke å hente URL:", url, e)
        return ""

    soup = BeautifulSoup(response.text, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()

    text = soup.get_text(separator="\n")
    lines = [line.strip() for line in text.splitlines()]
    lines = [line for line in lines if line]

    cleaned_text = "\n".join(lines)
    max_chars = 8000
    return cleaned_text[:max_chars] if len(cleaned_text) > max_chars else cleaned_text

@app.route("/fetch-answer", methods=["POST"])
def fetch_answer():
    data = request.json or {}

    question = (
        data.get("user_input")
        or data.get("message")
        or data.get("text")
        or data.get("question")
        or ""
    )

    print("🔍 Spørsmål mottatt:", question)

    if not question:
        return jsonify({"answer": "Jeg mottok ikke noe spørsmål."})

    q = question.lower()

    # Intent: pris
    if "klipp" in q or "pris" in q or "behandling" in q:
        answer = (
            "En klipp hos Adam og Eva varierer etter frisørens tittel:\n"
            "- Junior: 550 kr\n"
            "- Stylist: 1050 kr\n"
            "- Master Art Director: 1850 kr\n\n"
            "Du finner hele prislisten her: https://adamogeva.no/prisliste/"
        )
        return jsonify({"answer": answer})

    # Intent: booking
    elif "bestill" in q or "time" in q or "book" in q:
        answer = (
            "Du kan enkelt bestille time via vår nettside: https://adamogeva.no/bestill-time\n\n"
            "Velg ønsket salong og behandling, så finner du ledige tider. Vi gleder oss til å se deg!"
        )
        return jsonify({"answer": answer})

    # Intent: salonginfo
    elif "paleet" in q or "telefon" in q or "åpningstid" in q or "adresse" in q:
        answer = (
            "Adam og Eva Paleet ligger i Karl Johans gate 39, Oslo.\n"
            "- Telefon: 22 42 88 55\n"
            "- Åpningstider: Man–Fre 09:00–20:00, Lør 10:00–18:00\n\n"
            "Mer info: https://adamogeva.no/paleet"
        )
        return jsonify({"answer": answer})

    # Fallback: send til OpenAI med scraping
    scraped_text = scrape_page_text("https://adamogeva.no/prisliste/")

    system_prompt = BASE_SYSTEM_PROMPT + f"""

Her er prislisten og annen info hentet fra nettsiden:

{scraped_text}

Du kan også vise denne lenken til brukeren: https://adamogeva.no/prisliste/
"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": question}
        ]
    )

    answer = response.choices[0].message.content.strip()
    return jsonify({"answer": answer})

@app.route("/", methods=["GET"])
def home():
    return "Adam og Eva chatbot backend kjører."

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
