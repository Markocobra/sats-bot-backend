from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/chatbot", methods=["POST"])
def chatbot():
    data = request.get_json()
    question = data.get("question", "").lower().strip()

    # --- 1) Åpningstider ---
    opening_hours = {
        "storo": {"weekday": "06:00-22:00", "weekend": "08:00-20:00"},
        "nydalen": {"weekday": "06:00-22:00", "weekend": "08:00-20:00"},
        "bislett": {"weekday": "06:00-22:00", "weekend": "09:00-18:00"},
    }

    for center in opening_hours:
        if center in question:
            tider = opening_hours[center]
            reply = (
                f"Åpningstidene for {center.capitalize()}:\n"
                f"• Ukedager: {tider['weekday']}\n"
                f"• Helg: {tider['weekend']}"
            )
            return jsonify({"reply": reply})

    # --- 2) Medlemskap ---
    if "pris" in question or "medlemskap" in question:
        return jsonify({"reply":
            "Et SATS-medlemskap koster fra 549–749 kr/mnd avhengig av type. "
            "Vil du at jeg skal sende prislisten?"
        })

    # --- 3) Gruppetimer ---
    if "timer" in question or "gruppetimer" in question:
        return jsonify({"reply":
            "For gruppetimer, sjekk SATS-appen eller nettsiden. "
            "Hvilket senter vil du trene på?"
        })

    # --- 4) PT ---
    if "pt" in question or "personlig trener" in question:
        return jsonify({"reply":
            "Personlig trener starter fra 699 kr per time. "
            "Vil du at jeg skal finne PT-er for et bestemt senter?"
        })

    # --- 5) Standard fallback ---
    reply = (
        "Dette forstod jeg ikke helt 💡\n"
        "Prøv å spørre om:\n"
        "• Åpningstider\n"
        "• Medlemskap & priser\n"
        "• Gruppetimer\n"
        "• PT\n\n"
        "Hva vil du vite?"
    )

    return jsonify({"reply": reply})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
