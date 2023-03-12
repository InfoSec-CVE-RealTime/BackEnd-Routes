import flask
from web import app
from datetime import datetime
from web.models import CVE, MIN_DATE
from web.db import get_json_compatible


@app.route("/")
def home():
    return flask.jsonify({"message": "Hello World!"})


@app.route("/api/v1.0/top_cves")  # API ROUTE 1
def top_cves():
    min_date = get_arg("min_date", default=MIN_DATE, coerce_type=datetime)
    max_date = get_arg("max_date", default=datetime.now(), coerce_type=datetime)
    page = get_arg("page", default=1, coerce_type=int) - 1
    page_size = get_arg("page_size", default=10, coerce_type=int)
    if page < 0:
        page = 0
    if page_size > 500:
        page_size = 500
    if page_size < 1:
        page_size = 1
    cves = CVE.get_top_cves(min_date, max_date, page, page_size)
    return flask.jsonify(get_json_compatible(cves))


@app.route("/api/v1.0/access_complexity")  # API ROUTE 2
def access_complexity():
    min_date = get_arg("min_date", default=MIN_DATE, coerce_type=datetime)
    max_date = get_arg("max_date", default=datetime.now(), coerce_type=datetime)
    bin_size = get_arg("bin_size", default="year", choices=("month", "year"))
    data = CVE.get_binned_by_field("access_complexity", min_date, max_date, bin_size)
    return flask.jsonify(get_json_compatible(data))


def get_arg(arg_name, default=None, coerce_type=None, choices=()):
    if arg_name in flask.request.args:
        try:
            if coerce_type is datetime:
                value = datetime.strptime(flask.request.args.get(arg_name), "%Y-%m-%d")
            else:
                value = flask.request.args.get(arg_name, type=coerce_type)
        except (TypeError, ValueError):
            return default
        if choices and value not in choices:
            return default
        return value
    return default
