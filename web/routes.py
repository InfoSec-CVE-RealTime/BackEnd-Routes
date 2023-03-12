import flask
from web import app
from datetime import datetime
from web.models import CVE
from web.db import get_json_compatible


@app.route("/")
def home():
    return flask.jsonify({"message": "Hello World!"})


@app.route("/api/v1.0/top_cves")
def top_cves():
    min_date = get_arg("min_date", default=datetime(1970, 1, 1), coerce_type=datetime)
    max_date = get_arg("max_date", default=datetime.now(), coerce_type=datetime)
    page = get_arg("page", default=1, coerce_type=int) - 1
    page_size = get_arg("page_size", default=10, coerce_type=int)
    cves = CVE.get_top_cves(min_date, max_date, page, page_size)
    return flask.jsonify(get_json_compatible(cves))


def get_arg(property_name, default=None, coerce_type=None):
    if property_name in flask.request.args:
        return flask.request.args.get(property_name, type=coerce_type)
    return default
