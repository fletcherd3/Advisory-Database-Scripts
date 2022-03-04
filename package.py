import requests
import json
import time
import math

NPM_PAGE_SIZE = 36


def set_patched_versions(data):
    patched_versions = []
    for i in range(len(data['affected'])):
        patched_versions.append(add_patched_version(data, i))
    return patched_versions


def add_patched_version(data, i):
    if len(data['affected'][i]['ranges'][0]['events']) == 2:
        return data['affected'][i]['ranges'][0]['events'][1]['fixed']
    return 'None'


def set_affected_versions(data):
    affected_versions = []
    for i in range(len(data['affected'])):
        affected_versions.append(data['affected'][i]['ranges'][0]['events'][0]['introduced'])
    return affected_versions


class Package:
    def __init__(self, data):
        self.name = data['affected'][0]['package']['name']
        self.manager = data['affected'][0]['package']['ecosystem']
        self.affected_versions = set_affected_versions(data)
        self.patched_versions = set_patched_versions(data)
        self.dependants = self.set_dependants() if self.manager == "npm" else []

    def set_dependants(self):
        # time.sleep(0.05)  # APIs have a request limit, so may have to delay in between requests
        dependants = []
        if self.manager == 'npm':
            offset = 0
            for i in range(self.get_number_pages()):
                dependants += self.get_dependants(offset)
                offset += NPM_PAGE_SIZE
        else:
            dependants = self.get_dependants()
        return dependants

    def get_number_pages(self):
        res = requests.get('https://www.npmjs.com/package/{0}'.format(self.name))
        print(self.name)
        print(res.text)
        response = json.loads(res.text)
        return int(math.ceil(response['dependents']['dependentsCount']))

    def get_dependants(self, offset=0):
        res = requests.get(self.get_link(offset))
        return json.loads(res.text)

    def get_link(self, offset):
        if self.manager == 'RubyGames':
            return 'https://rubygems.org/api/v1/gems/{0}/reverse_dependencies.json'.format(self.name)
        elif self.manager == 'npm':
            return 'https://www.npmjs.com/browse/depended/{0}?offset={1}'.format(self.name, offset)

    def __str__(self):
        return "---------------------------------------------------\n" \
               "Package {0}:\n" \
               "Package Manager: {1}\n" \
               "Affected Versions: {2}\n" \
               "Patched Versions: {3}\n" \
               "Dependants: {4}\n" \
               "---------------------------------------------------\n".format
        (self.name, self.manager, self.affected_versions, self.patched_versions, self.dependants)
