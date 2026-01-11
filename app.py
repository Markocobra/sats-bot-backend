from flask import Flask, request, jsonify
import requests
import re
import os

app = Flask(__name__)

WP_API_URL = "https://adamogeva.no/wp-json/wp/v2/pages?per_page=100"

def clean_html(html):
    if not html:
        return ""
    return re.sub(r"<[^>]+>", "", html)

@app.route("/", methods=["GET"])
def health():
    return "OK", 200

@app.route("/fetch-answer", methods=["POST"])
def fetch_answer():
    # 🔒 Trygg parsing – krasjer aldri
    data = request.get_json(silent=True) or {}

    question = data.get("question")

    # ✅ Valider input
    if not isinstance(question, str) or not question.strip():
        return jsonify({
            "answer": "Jeg mottok ikke noe spørsmål. Prøv å skrive det én gang til 🙂"
        }), 200

    question = question.lower().strip()

    # 🔄 Hent sider fra WordPress
    try:
        r = requests.get(
            WP_API_URL,
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=10
        )
        r.raise_for_status()
        pages = r.json()
    except Exception:
        return jsonify({
            "answer": "Jeg fikk ikke kontakt med nettsiden akkurat nå."
        }), 200

    # 🔍 Søk i sider
    for page in pages:
        title = clean_html(page.get("title", {}).get("rendered", "")).lower()
        content = clean_html(page.get("content", {}).get("rendered", "")).lower()

        if question in title or question in content:
            return jsonify({
                "answer": clean_html(page.get("content", {}).get("rendered", ""))[:1200]
            }), 200

    # 🤷‍♂️ Fallback
    return jsonify({
        "answer": "Jeg fant ikke et direkte svar på adamogeva.no."
    }), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
