import os

from flask import Flask
from flask_cors import CORS

DEBUG = os.environ.get("DJANGO_DEBUG") == "1"
app = Flask(__name__)
CORS(app, origins=["https://app.example.com"])
app.debug = False


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
