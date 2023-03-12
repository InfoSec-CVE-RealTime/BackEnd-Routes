from web.db import db, BaseDocument, DataType
from datetime import datetime


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
