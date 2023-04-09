import flask
from web import app
from datetime import datetime
from web.models import CVE, Product, MIN_DATE, User
from web.db import get_json_compatible
from web.cwe_names.replace_cwe_codes_with_names import replace_cwe_codes_with_names


@app.route("/")
def home():
    return flask.jsonify({"message": "Hello World!"})


@app.route("/api/v1.0/signup", methods=["POST"])
def signup():
    email = flask.request.json.get("email")
    name = flask.request.json.get("name")
    password = flask.request.json.get("password")
    if not email or not password:
        return flask.jsonify({"message": "Email, name, and password are required."}), 400
    user = User.create(email, name, password)
    if not user:
        return flask.jsonify({"message": "User with that email already exists."}), 400
    return flask.jsonify({
        "user": {
            "email": user["email"],
            "name": user["name"]
        }
    }), 201


@app.route("/api/v1.0/login", methods=["POST"])
def login():
    email = flask.request.json.get("email")
    password = flask.request.json.get("password")
    if not email or not password:
        return flask.jsonify({"message": "Email and password are required."}), 400
    user = User.login(email, password)
    if not user:
        return flask.jsonify({"message": "Invalid email or password."}), 400
    return flask.jsonify({
        "user": {
            "email": user["email"],
            "name": user["name"]
        }
    }), 200


@app.route("/api/v1.0/top_cves")  # API ROUTE 1
def top_cves():
    min_date, max_date, page, page_size = get_top_data_args()
    cves = CVE.get_top_cves(min_date, max_date, page, page_size)
    return flask.jsonify(get_json_compatible(cves))


@app.route("/api/v1.0/access_complexity")  # API ROUTE 2
def access_complexity():
    min_date = get_arg("min_date", default=MIN_DATE, coerce_type=datetime)
    max_date = get_arg("max_date", default=datetime.now(), coerce_type=datetime)
    bin_size = get_arg("bin_size", default="year", choices=("month", "year"))
    data = CVE.get_binned_by_field("access_complexity", min_date, max_date, bin_size)
    return flask.jsonify(get_json_compatible(data))


@app.route("/api/v1.0/access_vector")  # API ROUTE 3
def access_vector():
    min_date = get_arg("min_date", default=MIN_DATE, coerce_type=datetime)
    max_date = get_arg("max_date", default=datetime.now(), coerce_type=datetime)
    bin_size = get_arg("bin_size", default="year", choices=("month", "year"))
    data = CVE.get_binned_by_field("access_vector", min_date, max_date, bin_size)
    return flask.jsonify(get_json_compatible(data))


@app.route("/api/v1.0/top_products")  # API ROUTE 4
def top_products():
    min_date, max_date, page, page_size = get_top_data_args()
    cves = Product.get_top_products(min_date, max_date, page, page_size)
    return flask.jsonify(get_json_compatible(cves))


@app.route("/api/v1.0/access_authentication")  # API ROUTE 5
def access_authentication():
    min_date = get_arg("min_date", default=MIN_DATE, coerce_type=datetime)
    max_date = get_arg("max_date", default=datetime.now(), coerce_type=datetime)
    bin_size = get_arg("bin_size", default="year", choices=("month", "year"))
    data = CVE.get_binned_by_field("access_authentication", min_date, max_date, bin_size)
    return flask.jsonify(get_json_compatible(data))


@app.route("/api/v1.0/impact_availability")  # API ROUTE 6
def impact_availability():
    min_date = get_arg("min_date", default=MIN_DATE, coerce_type=datetime)
    max_date = get_arg("max_date", default=datetime.now(), coerce_type=datetime)
    bin_size = get_arg("bin_size", default="year", choices=("month", "year"))
    data = CVE.get_binned_by_field("impact_availability", min_date, max_date, bin_size)
    return flask.jsonify(get_json_compatible(data))


@app.route("/api/v1.0/vulnerability_type")  # API ROUTE 7
def vulnerability_type():
    min_date = get_arg("min_date", default=MIN_DATE, coerce_type=datetime)
    max_date = get_arg("max_date", default=datetime.now(), coerce_type=datetime)
    bin_size = get_arg("bin_size", default="year", choices=("month", "year"))
    data = CVE.get_binned_by_field("cwe_code", min_date, max_date, bin_size)
    data = replace_cwe_codes_with_names(data)
    return flask.jsonify(get_json_compatible(data))


@app.route("/api/v1.0/threat_proliferation")  # API ROUTE 8
def threat_proliferation():
    min_date = get_arg("min_date", default=MIN_DATE, coerce_type=datetime)
    max_date = get_arg("max_date", default=datetime.now(), coerce_type=datetime)
    bin_size = get_arg("bin_size", default="year", choices=("month", "year"))
    data = CVE.get_threat_proliferation(min_date, max_date, bin_size)
    return flask.jsonify(get_json_compatible(data))


def get_top_data_args():
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
    return min_date, max_date, page, page_size


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
