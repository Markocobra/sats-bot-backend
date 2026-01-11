from flask import Flask, request, jsonify
import requests
import re

app = Flask(__name__)

WP_API_URL = "https://adamogeva.no/wp-json/wp/v2/pages"

def clean_html(raw_html):
    clean = re.compile("<.*?>")
    return re.sub(clean, "", raw_html)

@app.route("/fetch-answer", methods=["POST"])
def fetch_answer():
    data = request.get_json()
    question = data.get("question", "").lower()

    if not question:
        return jsonify({"answer": "Jeg forstod ikke spørsmålet."})

    try:
        response = requests.get(
            WP_API_URL,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        response.raise_for_status()
        pages = response.json()
    except Exception:
        return jsonify({"answer": "Klarte ikke hente innhold fra nettsiden akkurat nå."})

    best_match = None

    for page in pages:
        title = clean_html(page["title"]["rendered"]).lower()
        content = clean_html(page["content"]["rendered"]).lower()

        if question in title or question in content:
            best_match = page
            break

    if best_match:
        answer = clean_html(best_match["content"]["rendered"])[:1200]
    else:
        answer = (
            "Jeg fant ikke et direkte svar på nettsiden, "
            "men du kan prøve å formulere spørsmålet litt annerledes."
        )

    return jsonify({"answer": answer})
