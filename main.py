import json
from helpers import getListOfFiles


files = getListOfFiles('data/advisory-database/advisories/github-reviewed')
# files = getListOfFiles('advisory-database/advisories/unreviewed')
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
