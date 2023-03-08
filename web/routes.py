import flask
from web import app
from web.models import CVE


@app.route("/")
def home():
    return "Hello, World!"
