import json
from os import path
import csv
from datetime import datetime
from helpers import getListOfFiles, isValidVersion
from urllib.parse import quote

from pybraries.search import Search

eco_alias = {'crates.io': 'Cargo'}


search = Search()

file_path = path.join(*'data/advisory-database/advisories/github-reviewed'.split('/'))
files = getListOfFiles(file_path)

header = ['Name', 'Ecosystem', 'Severity', 'Version Introduced', 'Date Introduced', 'Version Fixed', 'Date Fixed']
with open('vulnerabilities.csv', 'w', newline='', encoding='UTF8') as csv_file:
    writer = csv.writer(csv_file)
    writer.writerow(header)
    v_count = 0

    for file_no, file in enumerate(files):
        f = open(file, 'r', encoding='utf-8')
        json_data = json.load(f)
        try:
            severity = json_data['database_specific']['severity']
            affected = json_data['affected'][0]
            # TODO: Use all events
            events = affected['ranges'][0]['events']  # For now, just use the first event

            ecosystem = affected['package']['ecosystem']
            if ecosystem in eco_alias:
                ecosystem = eco_alias[ecosystem]
            name = affected['package']['name']

            introduced_version = events[0]['introduced']
            fixed_version = events[1]['fixed']
            if not isValidVersion(introduced_version) or not isValidVersion(fixed_version):
                continue

            project = search.project(ecosystem, quote(name).replace('/', '%2F'))
            if project is None:
                continue
            prefix = 'v' if ecosystem in ['Go', 'Packagist'] else ''
            introduced_date = list(filter(lambda v: v['number'] == prefix + introduced_version, project['versions']))[0]['published_at']
            fixed_date = list(filter(lambda v: v['number'] == prefix + fixed_version, project['versions']))[0]['published_at']

            introduced_iso_date = str(datetime.fromisoformat(introduced_date.replace('Z', '+00:00')))
            fixed_iso_date = str(datetime.fromisoformat(fixed_date.replace('Z', '+00:00')))

            writer.writerow([name, ecosystem, severity, introduced_version, introduced_iso_date, fixed_version, fixed_iso_date])
            v_count += 1
            print(f"{v_count} dated vulnerabilities found. {(((file_no + 1) / len(files)) * 100):.2f}%")
        except IndexError:
            continue



