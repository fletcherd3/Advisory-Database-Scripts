import semver


def check_affected_versions(list_affected_versions, dependency_constraint):
    for version in list_affected_versions:
        if semver.satisfies(version, dependency_constraint):
            return True

    return False
