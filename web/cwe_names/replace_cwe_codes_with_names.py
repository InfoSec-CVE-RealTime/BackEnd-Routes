import os
import json

CWE_NAME_FILE = os.path.join(os.path.dirname(__file__), 'cwe_names.json')


def load_cwe_names():
    with open(CWE_NAME_FILE, 'r') as f:
        return json.load(f)


def replace_cwe_codes_with_names(items):
    cwe_names = load_cwe_names()
    new_items = []
    for item in items:
        new_item = {}
        for key, value in item.items():
            if key != "date":
                if str(key) in cwe_names:
                    name = cwe_names[str(key)]
                    new_item[name] = value
                else:
                    new_item[f"CWE {key} (Unknown)"] = value
            else:
                new_item[key] = value
        new_items.append(new_item)
    return new_items
