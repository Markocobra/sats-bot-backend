from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


@app.route("/chat", methods=["POST"])
def chat():
    data = request.get_json()
    question = data.get("user_question", "").lower().strip()

    # -------------------------------
    # 1) ÅPNINGSTIDER
    # -------------------------------
    opening_hours = {
        "storo": {"weekday": "06:00-22:00", "weekend": "08:00-20:00"},
        "nydalen": {"weekday": "06:00-22:00", "weekend": "08:00-20:00"},
        "bislett": {"weekday": "06:00-22:00", "weekend": "09:00-18:00"},
    }

    if "åpning" in question or "åpent" in question:
        for center in opening_hours:
            if center in question:
                times = opening_hours[center]
                return jsonify({
                    "reply": (
                        f"Åpningstidene for {center.capitalize()}:\n"
                        f"• Ukedager: {times['weekday']}\n"
                        f"• Helg: {times['weekend']}"
                    )
                })
        return jsonify({
            "reply": (
                "Hvilket SATS-senter er du interessert i? (Storo, Nydalen, Bislett)"
            )
        })


    # -------------------------------
    # 2) MEDLEMSKAP / PRISER
    # -------------------------------
    if "pris" in question or "koster" in question or "medlemskap" in question:
        return jsonify({
            "reply": (
                "Et SATS-medlemskap koster mellom 549–749 kr/mnd avhengig av type.\n"
                "Vil du se full prisliste?"
            )
        })


    # -------------------------------
    # 3) PERSONLIG TRENER (PT)
    # -------------------------------
    if "pt" in question or "personlig trener" in question:
        return jsonify({
            "reply": (
                "Personlig trener koster fra 699 kr per time.\n"
                "Ønsker du at jeg finner tilgjengelige PT-er på ditt senter?"
            )
        })


    # -------------------------------
    # 4) GRUPPETIMER
    # -------------------------------
    if "gruppetimer" in question or "timer" in question:
        return jsonify({
            "reply": (
                "Gruppetimer finner du i SATS-appen eller på nettsiden.\n"
                "Hvilket senter ønsker du gruppetimer for?"
            )
        })


    # -------------------------------
    # 5) FRYSE MEDLEMSKAP
    # -------------------------------
    if "fryse" in question or "pause" in question:
        return jsonify({
            "reply": (
                "Du kan fryse medlemskapet i opptil 60 dager per år via SATS-appen.\n"
                "Ønsker du at jeg viser deg hvordan?"
            )
        })


    # -------------------------------
    # 6) STANDARD SVAR (fallback)
    # -------------------------------
    return jsonify({
        "reply": (
            f"Du spurte: «{question}»\n"
            "Dette spørsmålet kan jeg ikke svare på ennå 🙏\n"
            "Men jeg jobber med å lære mer!\n\n"
            "Du kan spørre meg om:\n"
            "• Åpningstider\n"
            "• Medlemskap & priser\n"
            "• PT\n"
            "• Gruppetimer\n"
            "• Frysing av medlemskap\n"
        )
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
