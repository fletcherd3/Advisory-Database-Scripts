import json
import os
from helpers import getListOfFiles
from pathlib import Path

path = Path('data/advisory-database/advisories/github-reviewed')
# path = Path('data/advisory-database/advisories/unreviewed')
files = getListOfFiles(path)

counts = dict()

for file in files:
    f = open(file)
    json_data = json.load(f)
    if len(json_data['affected']):
        ecosystem = json_data['affected'][0]['package']['ecosystem']
        if ecosystem in counts:
            counts[ecosystem] += 1
        else:
            counts[ecosystem] = 1

print("Vulnerabilities per package manager\n")
for key in counts:
    print(key, counts[key])
