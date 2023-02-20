from web.db import db, BaseDocument, DataType, ListType
from datetime import datetime


class Vulnerability(BaseDocument):
    collection = db.test
    fields = {
        "cve_id": DataType(str, nullable=False),
        "created_at": DataType(datetime, nullable=False),
        "updated_at": DataType(datetime, nullable=False),
        "cvss": ListType(DataType(float), nullable=False),
        "vendors": ListType(DataType(str), nullable=False),
        "products": ListType(DataType(str), nullable=False),
        "cwe_codes": ListType(DataType(int), nullable=False),
        "cwe_names": ListType(DataType(str)),
        "description": DataType(str, nullable=False),
        "description_lang": DataType(str, nullable=False, default="en"),
        "access_vector": DataType(str, nullable=False),
        "access_complexity": DataType(str, nullable=False),
        "access_authentication": DataType(str, nullable=False)
    }
