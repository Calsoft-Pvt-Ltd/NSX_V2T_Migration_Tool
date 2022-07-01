from git import Repo
import json
import os
import requests
import yaml

PWD = os.getcwd()
RELEASE_INFO_FILE = os.path.join(PWD, 'src', 'release.yml')
REQUIREMENTS_FILE = os.path.join(PWD, 'src', 'requirements.txt')
PROV_DATA_FILE = os.path.join(PWD, 'provenanceData', 'v2t_provenance_data_2.5.json')


def read_build_info():
    with open(RELEASE_INFO_FILE) as f:
        file_data = yaml.safe_load(f)

    return file_data['Build']


def get_version():
    build = read_build_info()
    return build[1:]


def get_build():
    build = read_build_info()
    return build[1:]


def get_git_info():
    repo = Repo(PWD)
    branch = repo.head.reference.name
    assert branch == read_build_info()
    return {
        "host": repo.remotes.origin.url.split(':')[0].split('@')[1],
        "protocol": "git",
        "branch": branch,
        "ref": repo.head.commit.hexsha,
        "repo": repo.remotes.origin.url.split(':')[-1].split('.')[0]
    }


def get_packages_path():
    with open(REQUIREMENTS_FILE) as f:
        packages = f.readlines()

    package_paths = []
    for package in packages:
        package_name, package_version = package.strip('\n').split('==')
        response = requests.get(f"https://pypi.org/pypi/{package_name}/json", verify=False)
        response_data = response.json()
        version_info = response_data['releases'][package_version]

        for version_type in version_info:
            if version_type.get('packagetype') == 'sdist':
                package_paths.append(version_type['url'].split('/', 3)[-1])
                break
        else:
            package_paths.append(version_info[0]['url'].split('/', 3)[-1])

    return package_paths


if __name__ == '__main__':
    git_info = get_git_info()
    prov_data = {
      "id": "http://vmware.com/schemas/software_provenance-0.2.5.json",
      "tools": {
        "manual": None
      },
      "root": "vcd-v2t",
      "all_components": {
        "vcd-v2t": {
          "typename": "comp.build.manual",
          "name": "VMware NSX Migration for VMware Cloud Director",
          "version": get_version(),
          "build_number": get_build(),
          "buildtype": "release",
          "source_repositories": [
            {
              "content": "source",
              "host": git_info['host'],
              "protocol": "git",
              "paths": [
                "/"
              ],
              "branch": git_info['branch'],
              "ref": git_info['ref'],
              "repo": git_info['repo'],
            }
          ],
          "artifact_repositories": [
            {
              "content": "binary",
              "host": "files.pythonhosted.org",
              "protocol": "https",
              "paths": get_packages_path()
            }
          ]
        }
      }
    }

    with open(PROV_DATA_FILE, 'w') as prov_file:
        json.dump(prov_data, prov_file, indent=2)
