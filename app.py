@app.route("/fetch-answer", methods=["POST"])
def fetch_answer():
    data = request.get_json(silent=True) or {}

    question = data.get("question")

    if not isinstance(question, str) or not question.strip():
        return jsonify({
            "answer": "Jeg mottok ikke noe spørsmål. Prøv å skrive det én gang til 🙂"
        })

    question = question.lower()

    try:
        r = requests.get(
            "https://adamogeva.no/wp-json/wp/v2/pages",
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=10
        )
        r.raise_for_status()
        pages = r.json()
    except Exception:
        return jsonify({
            "answer": "Jeg fikk ikke kontakt med nettsiden akkurat nå."
        })

    for page in pages:
        title = clean_html(page["title"]["rendered"]).lower()
        content = clean_html(page["content"]["rendered"]).lower()

        if question in title or question in content:
            return jsonify({
                "answer": clean_html(page["content"]["rendered"])[:1000]
            })

    return jsonify({
        "answer": "Jeg fant ikke et direkte svar på adamogeva.no."
    })
