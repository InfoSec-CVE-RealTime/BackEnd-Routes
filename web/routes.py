from flask import Flask
from web import app
from web.models import Test
from datetime import datetime


@app.route("/")
def home():
    test = Test({"name": "test", "time": datetime.utcnow()})
    test.push()
    return "Hello, World!"
