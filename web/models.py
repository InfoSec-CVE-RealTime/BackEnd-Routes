from web.db import db, BaseDocument, DataType, ReferenceType
from datetime import datetime


class CVE(BaseDocument):
    collection = db.cve
    fields = {
        "cve_id": DataType(str, nullable=False),
        "pub_date": DataType(datetime, nullable=False),
        "mod_date": DataType(datetime, nullable=False),
        "cvss": DataType(float, nullable=False),
        # "vendors": ListType(DataType(str), nullable=False),  # suggested add
        # "products": ListType(DataType(str), nullable=False),  # suggested add
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


class Product(BaseDocument):
    collection = db.products
    fields = {
        "cve_id": DataType(str, nullable=False),  # suggested remove
        "vulnerable_product": DataType(str, nullable=False)  # suggested rename to "product_name"
    }


class VendorProduct(BaseDocument):
    collection = db.vendor_products
    fields = {
        "": DataType(int, nullable=False),  # suggested remove
        "vendor": DataType(str, nullable=False),  # suggested rename to "vendor_name"
        "product": DataType(str, nullable=False)  # suggested rename to "product_name"
    }


class Vendor(BaseDocument):
    collection = db.vendors
    fields = {
        "cve_id": DataType(str, nullable=False),  # suggested remove
        "vendor": DataType(str, nullable=False)  # suggested rename to "vendor_name"
    }
