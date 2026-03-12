import json
from langchain_openai import OpenAIEmbeddings
from langchain.vectorstores import FAISS

with open("website_data.json", "r", encoding="utf-8") as f:
    pages = json.load(f)

texts = [p["text"] for p in pages]

embeddings = OpenAIEmbeddings()

vectorstore = FAISS.from_texts(texts, embeddings)

vectorstore.save_local("website_index")

print("Embeddings ferdig!")