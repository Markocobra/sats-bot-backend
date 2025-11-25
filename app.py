from flask import Flask, request, jsonify

app = Flask(__name__)

# Test-endepunkt for Render
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200

# API-endepunkt for åpningstider
@app.route("/opening-hours", methods=["POST"])
def opening_hours():
    data = request.get_json()
    gym_navn = data.get("senter", "").strip()

    åpningstider = {
        "Storo": {"weekday": "06:00-22:00", "weekend": "08:00-20:00"},
        "Nydalen": {"weekday": "06:00-22:00", "weekend": "08:00-20:00"},
        "Bislett": {"weekday": "06:00-22:00", "weekend": "09:00-18:00"},
    }

    svar = åpningstider.get(gym_navn, {"weekday": "Ukjent", "weekend": "Ukjent"})

    return jsonify({
        "senter": gym_navn,
        "ukedager": svar["weekday"],
        "helg": svar["weekend"]
    })

# Lokalt kjøring – Render bruker gunicorn via Procfile
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
