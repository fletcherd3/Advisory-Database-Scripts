import json
import csv
from os import path
from helpers import get_list_of_files


def withdrawn(data):
    return 'withdrawn' in data


def valid_vulnerability(data):
    return len(data['affected']) > 0


file_path = path.join(*'data/advisory-database/advisories/github-reviewed'.split('/'))
files = get_list_of_files(file_path)

output_file = open("vulnerabilities.csv", "w", newline='')
writer = csv.writer(output_file)

output_data = dict()

for file in files:
    input_file = open(file, 'r', encoding='utf-8')
    json_data = json.load(input_file)
    if valid_vulnerability(json_data) and not withdrawn(json_data):
        year_discovered = json_data['aliases'][0].split('-')[1] if len(json_data['aliases']) > 0 else json_data['published'].split('-')[0]
        severity = json_data['database_specific']['severity']
        if year_discovered in output_data:
            if severity in output_data[year_discovered]:
                output_data[year_discovered][severity] += 1
            else:
                output_data[year_discovered][severity] = 1
        else:
            output_data[year_discovered] = dict()
            output_data[year_discovered][severity] = 1

for year, severities in output_data.items():
    row = [year]
    for severity, number_vulnerabilities in severities.items():
        row.append((severity, number_vulnerabilities))
    writer.writerow(row)


output_file.close()

