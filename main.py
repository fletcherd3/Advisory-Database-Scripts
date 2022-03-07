from datetime import datetime
from asyncio.windows_events import NULL
import json
import requests
from os import path
from helpers import getListOfFiles
from pybraries.search import Search

search = Search()
file_path = path.join(*'data/advisory-database/advisories/github-reviewed'.split('/'))
files = getListOfFiles(file_path)

counts = dict()
found = 0

for file in files:
    f = open(file, 'r', encoding='utf-8')
    json_data = json.load(f)
    if len(json_data['affected']):
        ecosystem = json_data['affected'][0]['package']['ecosystem']
        ecosystem = ecosystem.lower()
        if ecosystem == 'crates.io':
            ecosystem = "cargo"

        print(ecosystem)
        package = json_data['affected'][0]['package']['name']
        severity = json_data['database_specific']['severity']
        introduced = json_data['affected'][0]['ranges'][0]['events'][0]['introduced']
        published = datetime.strptime(json_data['published'], "%Y-%m-%dT%H:%M:%SZ")

        # Get Fixed
        fixed = NULL
        try:
            fixed = json_data['affected'][0]['ranges'][0]['events'][1]['fixed']
        except IndexError:
            pass

        if ecosystem not in counts:
            counts[ecosystem] = dict()
            counts[ecosystem]['fixed'] = dict()
            counts[ecosystem]['fixed']['before_published'] = dict()
            counts[ecosystem]['fixed']['after_published'] = dict()
            counts[ecosystem]['unfixed'] = dict()

        if fixed:
            info = NULL

            # Using search to find packagist and go packages due to oddities with package names
            # Not perfect but works in most cases
            if ecosystem == 'packagist' or ecosystem == 'go':
                info = search.project_search(keywords=package, platform=ecosystem)
                if len(info) >= 1:
                    # Get first value in the search query
                    info = info[0]
            else:
                info = search.project(ecosystem, package)

            if info:
                found += 1
                print("Found:", found)
                after_publish = False
                for release in info['versions']:
                    if release['number'] == fixed:
                        fixed_version_release = datetime.strptime(release['published_at'], "%Y-%m-%dT%H:%M:%S.%fZ")
                        after_publish = fixed_version_release > published
                        break

                # Could output to file but felt this was fine for now
                if after_publish:
                    if severity not in counts[ecosystem]['fixed']['after_published']:
                        counts[ecosystem]['fixed']['after_published'][severity] = 1
                    else:
                        counts[ecosystem]['fixed']['after_published'][severity] += 1
                else:
                    if severity not in counts[ecosystem]['fixed']['before_published']:
                        counts[ecosystem]['fixed']['before_published'][severity] = 1
                    else:
                        counts[ecosystem]['fixed']['before_published'][severity] += 1
            else:
                print('Could not find package:' + package + '. For ecosystem:' + ecosystem)
        else:
            if severity not in counts[ecosystem]['unfixed']:
                counts[ecosystem]['unfixed'][severity] = 1
            else:
                counts[ecosystem]['unfixed'][severity] += 1
    f.close()


print("Fixed vulnerabilities per package manager\n")
for key in counts:
    print(key, counts[key])
