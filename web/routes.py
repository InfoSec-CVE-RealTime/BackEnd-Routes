import flask
from flask_cors import cross_origin
import traceback
from web import app
from datetime import datetime, timedelta
from web.models import CVE, Product, MIN_DATE, MAX_DATE, User, Vendor
from web.db import get_json_compatible
from web.cwe_names.replace_cwe_codes_with_names import replace_cwe_codes_with_names


@app.route("/")
def home():
    return flask.jsonify({"message": "Hello World!"})


@app.route("/api/v1.0/signup", methods=["POST"])
@cross_origin()
def signup():
    data = flask.request.get_json()
    # print(data)
    email = data.get("email")
    name = data.get("name")
    password = data.get("password")
    print()
    if not email or not password:
        return flask.jsonify({"message": "Email, name, and password are required."}), 400
    try:
        user = User.create(email, name, password)
    except Exception:
        traceback.print_exc()
        return flask.jsonify({"message": "An error occurred while creating the user."}), 500
    if not user:
        return flask.jsonify({"message": "User with that email already exists."}), 400
    return flask.jsonify({
        "user": {
            "user_id": str(user["_id"]),
            "email": user["email"],
            "name": user["name"],
            "subscribed": user["subscribed"]
        }
    }), 201


@app.route("/api/v1.0/login", methods=["POST"])
# @cross_origin(origin='localhost',headers=['Content-Type','Authorization'])
@cross_origin()
def login():
    email = flask.request.json.get("email")
    password = flask.request.json.get("password")
    if not email or not password:
        return flask.jsonify({"message": "Email and password are required."}), 400
    user = User.login(email, password)
    if user is None:
        return flask.jsonify({"message": "Invalid email or password."}), 400
    response = flask.jsonify(
        {
            "user_id": str(user["_id"]),
            "email": email,
            "name": password,
            "subscribed": user["subscribed"]
        }
    )
    # response.headers.add("Access-Control-Allow-Origin", "*")
    # response.headers.add("Access-Control-Allow-Headers", "*")
    # response.headers.add("Access-Control-Allow-Methods", "*")
    return response, 200


@app.route("/api/v1.0/user_session", methods=["POST"])
def get_user_session():
    user_id = flask.request.json.get("user_id")
    if not user_id:
        return flask.jsonify({"message": "No user session found."}), 404
    user = User.from_id(user_id)
    if not user:
        return flask.jsonify({"message": "No user session found."}), 404
    return flask.jsonify({
        "user": {
            "user_id": str(user["_id"]),
            "email": user["email"],
            "name": user["name"],
            "subscribed": user["subscribed"]
        }
    }), 200


@app.route("/api/v1.0/set_subscription", methods=["POST"])
def set_subscription():
    user_id = flask.request.json.get("user_id")
    subscribe = bool(flask.request.json.get("subscribe"))
    user = User.from_id(user_id)
    if not user:
        return flask.jsonify({"message": "No user session found."}), 404
    user["subscribed"] = subscribe
    user.push()
    return flask.jsonify({
        "user": {
            "user_id": str(user["_id"]),
            "email": user["email"],
            "name": user["name"],
            "subscribed": user["subscribed"]
        }}), 200


@app.route("/api/v1.0/top_cves")  # API ROUTE 1
def top_cves():
    min_date, max_date = get_date_args()
    page, page_size = get_top_data_args()
    cves = CVE.get_top_cves(min_date, max_date, page, page_size)
    return flask.jsonify(get_json_compatible(cves))


@app.route("/api/v1.0/access_complexity")  # API ROUTE 2
def access_complexity():
    min_date, max_date = get_date_args()
    bin_size = get_arg("bin_size", default="year", choices=("month", "year"))
    data = CVE.get_binned_by_field("access_complexity", min_date, max_date, bin_size)
    return flask.jsonify(get_json_compatible(data))


@app.route("/api/v1.0/access_vector")  # API ROUTE 3
def access_vector():
    min_date, max_date = get_date_args()
    bin_size = get_arg("bin_size", default="year", choices=("month", "year"))
    data = CVE.get_binned_by_field("access_vector", min_date, max_date, bin_size)
    return flask.jsonify(get_json_compatible(data))


@app.route("/api/v1.0/top_products")  # API ROUTE 4
def top_products():
    min_year, _ = get_year_args()
    page, page_size = get_top_data_args()
    data = Product.get_top_products(min_year, page, page_size)
    return flask.jsonify(get_json_compatible(data))


@app.route("/api/v1.0/access_authentication")  # API ROUTE 5
def access_authentication():
    min_date = get_arg("min_date", default=MIN_DATE, coerce_type=datetime)
    max_date = get_arg("max_date", default=datetime.now(), coerce_type=datetime)
    bin_size = get_arg("bin_size", default="year", choices=("month", "year"))
    data = CVE.get_binned_by_field("access_authentication", min_date, max_date, bin_size)
    return flask.jsonify(get_json_compatible(data))


@app.route("/api/v1.0/impact_availability")  # API ROUTE 6
def impact_availability():
    min_date, max_date = get_date_args()
    bin_size = get_arg("bin_size", default="year", choices=("month", "year"))
    data = CVE.get_binned_by_field("impact_availability", min_date, max_date, bin_size)
    return flask.jsonify(get_json_compatible(data))


@app.route("/api/v1.0/vulnerability_type")  # API ROUTE 7
def vulnerability_type():
    min_date, max_date = get_date_args()
    bin_size = get_arg("bin_size", default="month", choices=("month", "year"))
    data = CVE.get_binned_by_field("cwe_code", min_date, max_date, bin_size)
    data = replace_cwe_codes_with_names(data)
    data = filter_top_items(data, 5)
    return flask.jsonify(get_json_compatible(data))


def filter_top_items(data, top_number):
    totals = {}
    for block in data:
        for item in block:
            if item in ["date", "Unclassified Vulnerability"]:
                continue
            totals[item] = totals.get(item, 0) + block[item]
    top_items = sorted(totals, key=totals.get, reverse=True)[:top_number]
    filtered_data = []
    for block in data:
        # skip years before 2008
        year = int(block["date"][:4])
        if year < 2013:
            continue
        filtered_block = {"date": block["date"]}
        for item in top_items:
            filtered_block[item] = block.get(item, 0)
        filtered_data.append(filtered_block)
    return filtered_data


@app.route("/api/v1.0/threat_proliferation")  # API ROUTE 8
def threat_proliferation():
    min_date, max_date = get_date_args()
    bin_size = get_arg("bin_size", default="month", choices=("month", "year"))
    data = CVE.get_threat_proliferation(min_date, max_date, bin_size)
    return flask.jsonify(get_json_compatible(data))


@app.route("/api/v1.0/top_vendors")  # API ROUTE 9
def top_vendors():
    min_year, _ = get_year_args()
    page, page_size = get_top_data_args()
    data = Vendor.get_top_vendors(min_year, page, page_size)
    return flask.jsonify(get_json_compatible(data))


@app.route("/api/v1.0/get_products")  # API ROUTE 10
def get_products():
    products = Product.get_unique_products()
    return flask.jsonify(get_json_compatible(products))


@app.route("/api/v1.0/get_vendors")  # API ROUTE 11
def get_vendors():
    vendors = Vendor.get_unique_vendors()
    return flask.jsonify(get_json_compatible(vendors))


@app.route("/api/v1.0/product_history")  # API ROUTE 12
def product_history():
    products = flask.request.args.get("products") or ""
    products = products.split(",")
    min_date, max_date = get_year_args()
    data = Product.get_product_history(products, min_date, max_date)
    data = get_history_totals(products, data)
    return flask.jsonify(get_json_compatible(data))


@app.route("/api/v1.0/vendor_history")  # API ROUTE 13
def vendor_history():
    vendors = flask.request.args.get("vendors") or ""
    vendors = vendors.split(",")
    min_date, max_date = get_year_args()
    data = Vendor.get_vendor_history(vendors, min_date, max_date)
    data = get_history_totals(vendors, data)
    return flask.jsonify(get_json_compatible(data))


def get_history_totals(products, data):
    new_blocks = []
    for block in data:
        new_block = {"date": block["year"], "total": 0}
        for product in products:
            new_block[product] = block.get(product, 0)
            new_block["total"] += new_block[product]
        new_blocks.append(new_block)
    return new_blocks


def get_year_args():
    duration = get_arg("duration", default="all", choices=("1y", "3y", "5y", "10y", "all"))
    if duration == "all":
        min_year = MIN_DATE.year
    else:
        min_year = MAX_DATE.year - int(duration[:-1])
    return min_year, MAX_DATE.year


def get_date_args():
    """Have an argument called 'duration' that is a string of the form '1d', '4d', '1w', '1m', '3m', '6m', '1y',
    '3y', '5y', '10y', 'all' (default). Turn that into min_date and max_date variables."""
    duration = get_arg("duration", default="all",
                       choices=("1m", "3m", "6m", "1y", "3y", "5y", "10y", "all"))
    time_deltas = {
        "1m": timedelta(weeks=4),
        "3m": timedelta(weeks=12),
        "6m": timedelta(weeks=26),
        "1y": timedelta(weeks=52),
        "3y": timedelta(weeks=52 * 3),
        "5y": timedelta(weeks=52 * 5),
        "10y": timedelta(weeks=52 * 10),
    }
    if duration == "all":
        min_date = MIN_DATE
    else:
        min_date = MAX_DATE - time_deltas[duration]
    return min_date, MAX_DATE


def get_top_data_args():
    page = get_arg("page", default=1, coerce_type=int) - 1
    page_size = get_arg("page_size", default=10, coerce_type=int)
    if page < 0:
        page = 0
    if page_size > 500:
        page_size = 500
    if page_size < 1:
        page_size = 1
    return page, page_size


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
