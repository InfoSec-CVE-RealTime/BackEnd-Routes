from web.db import db, BaseDocument, DataType
from datetime import datetime

MIN_DATE = datetime(1988, 1, 1)


class CVE(BaseDocument):
    collection = db.cve
    fields = {
        "cve_id": DataType(str, nullable=False),
        "pub_date": DataType(datetime, nullable=False),
        "mod_date": DataType(datetime, nullable=False),
        "cvss": DataType(float, nullable=False),
        "cwe_code": DataType(int, nullable=False),
        "cwe_name": DataType(str, nullable=False),
        "summary": DataType(str, nullable=False),
        "access_vector": DataType(str, nullable=False),
        "access_complexity": DataType(str, nullable=False),
        "access_authentication": DataType(str, nullable=False),
        "impact_availability": DataType(str, nullable=False),
        "impact_confidentiality": DataType(str, nullable=False),
        "impact_integrity": DataType(str, nullable=False)
    }

    @classmethod
    def get_top_cves(cls, min_date, max_date, page, page_size, as_dicts=True):
        cves = cls.collection.aggregate([
            {"$match": {"pub_date": {"$gte": min_date, "$lte": max_date}}},
            {"$sort": {"cvss": -1}},
            {"$skip": page * page_size},
            {"$limit": page_size}
        ])
        return list(cves) if as_dicts else [cls(cve) for cve in cves]

    @classmethod
    def get_binned_by_field(cls, field, min_date, max_date, bin_size):
        date_format = cls.get_bin_aggregate_date_format(bin_size)
        cves = cls.collection.aggregate([
            {"$match": {"pub_date": {"$gte": min_date, "$lte": max_date}}},
            {"$project": {"pub_date": 1, field: 1}},
            {"$group": {
                "_id": {
                    "field": "$" + field,
                    "date": {"$dateToString": {"format": date_format, "date": "$pub_date"}}
                },
                "count": {"$sum": 1}
            }},
            {"$sort": {"_id.date": 1}}
        ])
        data = cls.collect_data_by_bin(list(cves), min_date, max_date, bin_size)
        return data

    @classmethod
    def collect_data_by_bin(cls, cves, min_date, max_date, bin_size):
        data = []
        date_format = cls.get_bin_aggregate_date_format(bin_size)
        current_date = min_date
        while current_date <= max_date:
            data_date = current_date.strftime(date_format)
            current_bin = {"date": current_date.strftime("%Y-%m-%d")}
            for cve in cves:
                if cve["_id"]["date"] == data_date and cve["_id"].get("field"):
                    current_bin[cve["_id"]["field"]] = cve["count"]
            data.append(current_bin)
            current_date = cls.get_next_bin_date(current_date, bin_size)
        return data

    @classmethod
    def get_bin_aggregate_date_format(cls, bin_size):
        if bin_size == "month":
            return "%Y-%m"
        else:  # bin_size == "year"
            return "%Y"

    @classmethod
    def get_next_bin_date(cls, current_date, bin_size):
        if bin_size == "year":
            return current_date.replace(year=current_date.year + 1)
        else:  # bin_size == "month"
            next_month = current_date.month + 1 if current_date.month < 12 else 1
            next_year = current_date.year + 1 if next_month == 1 else current_date.year
            return current_date.replace(year=next_year, month=next_month)


class Product(BaseDocument):
    collection = db.products
    fields = {
        "cve_id": DataType(str, nullable=False),
        "vulnerable_product": DataType(str, nullable=False)
    }


class VendorProduct(BaseDocument):
    collection = db.vendor_products
    fields = {
        "vendor": DataType(str, nullable=False),
        "product": DataType(str, nullable=False)
    }


class Vendor(BaseDocument):
    collection = db.vendors
    fields = {
        "cve_id": DataType(str, nullable=False),
        "vendor": DataType(str, nullable=False)
    }
