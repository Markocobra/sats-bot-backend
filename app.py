import os
import requests
from flask import Flask, request, jsonify
from bs4 import BeautifulSoup
from openai import OpenAI

app = Flask(__name__)

# OpenAI-klient (leser nøkkel fra Render Environment)
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

WP_API_URL = "https://adamogeva.no/wp-json/wp/v2/pages?per_page=100"

def fetch_pages():
    res = requests.get(WP_API_URL, timeout=15)
    res.raise_for_status()
    return res.json()

def clean_html(html):
    soup = BeautifulSoup(html, "html.parser")
    return soup.get_text(separator=" ", strip=True)

def build_knowledge_base():
    pages = fetch_pages()
    docs = []

    for page in pages:
        title = page.get("title", {}).get("rendered", "")
        content = page.get("content", {}).get("rendered", "")
        text = clean_html(content)

        if text:
            docs.append(f"TITTEL: {title}\nINNHOLD: {text}")

    return "\n\n---\n\n".join(docs)

# ⚠️ bygges én gang ved oppstart
KNOWLEDGE_BASE = build_knowledge_base()

@app.route("/fetch-answer", methods=["POST"])
def fetch_answer():
    data = request.get_json(silent=True) or {}
    question = data.get("question", "").strip()

    if not question:
        return jsonify({
            "answer": "Jeg fikk ikke med meg spørsmålet ditt."
        })

    prompt = f"""
Du er en hjelpsom kundeservice-chatbot for frisørkjeden Adam og Eva.

Svar KUN basert på informasjonen under.
Hvis svaret ikke finnes i teksten, si tydelig at du ikke finner det på adamogeva.no.

INFORMASJON:
{KNOWLEDGE_BASE}

SPØRSMÅL:
{question}
"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "user", "content": prompt}
        ]
    )

    answer = response.choices[0].message.content.strip()

    return jsonify({
        "answer": answer
    })

@app.route("/")
def health():
    return "OK"
