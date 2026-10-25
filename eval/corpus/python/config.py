import ssl

import requests
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from flask import Flask

DEBUG = True  # expect: CM-C003

api = FastAPI(debug=True)  # expect: CM-C003
api.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)  # expect: CM-J004

app = Flask(__name__)
app.config["DEBUG"] = True  # expect: CM-C003


def fetch(url):
    return requests.get(url, verify=False)  # expect: CM-A006, CM-D007


def insecure_context():
    return ssl._create_unverified_context()  # expect: CM-D007


def safe_fetch(url):
    return requests.get(url, timeout=10)


if __name__ == "__main__":
    app.run(debug=True)  # expect: CM-A005
