from flask import Flask, request, jsonify
import requests
from bs4 import BeautifulSoup

app = Flask(__name__)

@app.route("/fetch-answer", methods=["POST"])
def fetch_answer():
    data = request.get_json()
    question = data.get("question", "")

    url = "https://dinside.no/faq"
    html = requests.get(url, timeout=10).text
    soup = BeautifulSoup(html, "html.parser")
    page_text = soup.get_text(" ", strip=True).lower()

    if question.lower() in page_text:
        answer = "Jeg fant relevant informasjon på nettsiden."
    else:
        answer = "Jeg fant ikke et tydelig svar."

    return jsonify({"answer": answer})

if __name__ == "__main__":
    app.run()
