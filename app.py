from flask import Flask, request, jsonify
from openai import OpenAI
import os

app = Flask(__name__)

# OpenAI-klient (Render: legg inn OPENAI_API_KEY i Environment)
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Systemprompt – gir modellen rollen sin
SYSTEM_PROMPT = """
Du er en hjelpsom chatbot for frisørkjeden Adam og Eva.
Du svarer på spørsmål om:
- behandlinger
- priser
- åpningstider
- booking
- produkter
- generelle spørsmål om frisørkjeden

Hvis du ikke vet svaret, si det på en profesjonell måte.
Svar alltid på norsk.
"""

@app.route("/fetch-answer", methods=["POST"])
def fetch_answer():
    data = request.json

    # Landbot sender vanligvis "user_input", men sjekk hva du bruker
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

    # Send spørsmålet til OpenAI
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
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
