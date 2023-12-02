
import os
import json
import requests
import base64
import csv
import parsing_git_commits
from urllib.parse import urlparse

access_token = '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'

#Set up headers with the access token
headers = {
    'Authorization': f'token {access_token}',
    'Accept': 'application/vnd.github.v3+json'
}

def get_cargo_toml_content(owner, repo):
    # url = f'https://crates.io/api/v1/crates?q={cargo_package_name}'
    # response = requests.get(url, headers={'User-Agent': 'esinyavin01@gmail.com'})
    # return response.json()
    url = f'https://api.github.com/repos/{owner}/{repo}/contents/Cargo.toml'
    response = requests.get(url, headers=headers)
    content = response.json()['content']
    return base64.b64decode(content).decode('utf-8')

def get_dependents(cargo_package_name):
    url = f'https://crates.io/api/v1/crates/{cargo_package_name}/reverse_dependencies'
    response = requests.get(url, headers={'User-Agent':'esinyavin01@gmail.com'})
    if response.status_code == 200:
        result = {}
        for version in response.json()['versions']:
            if version['published_by'] == None or version['published_by'] == None:
                print("github unavailable for cargo_package_name {cargo_package_name} and dependent {version}")
                result[version['crate']] = {'downloads':version['downloads'], 'github_url': ""}
                continue
            print(version)
            result[version['crate']] = {'downloads':version['downloads'], 'github_url': version['published_by']['url'], 'version':version['num']}
        return result
    else:
        return "Failed finding dependents"
    
#get minimum version of dependent that can be used (basically ignore ~ and ^). 
def get_version_of_dependency(dependent, version, dependency):
    url = f'https://crates.io/api/v1/crates/{dependent}/{version}/dependencies'
    response = requests.get(url, headers={'User-Agent':'esinyavin01@gmail.com'})
    if response.status_code == 200:
        for dep in response.json()["dependencies"]:
            if dep['crate_id'] == dependency:
                # if '~' in dep['req']:
                #     print('~ in req for dependent ' + dependent + ' and dependency ' + dependency)
                # return dep['req'].replace('^', '')
                return dep['req'].replace('^', '').replace('~', '')
    else:
        return "Failed finding dependency version"
    
# def get_latest_version(dependent):
#     url = f'https://crates.io/api/v1/crates/{dependent}'
#     response = requests.get(url, headers={'User-Agent':'esinyavin01@gmail.com'})
#     if response.status_code == 200:
#         for dep in response.json()["dependencies"]:
#             if dep['crate_id'] == dependency:
#                 return dep['req'].replace('^', '').replace('~', '')
#     else:
#         return "Failed finding dependency version"
    
def json_to_row(file_path: str):
    """Given a file path to a json file in the OSV format, returns a populated dataframe."""
    with open(file_path, 'r') as file:
        data = json.load(file)
    if "withdrawn" in data:
        return None
    
    res = []
    if not data["affected"]:
        return res
    
    for affected in data["affected"]:
        #filter out for not crates.io
        
        if not affected["package"] or not affected["package"]["ecosystem"] or affected["package"]["ecosystem"] != "crates.io":
            return
        
        row = []
        row.append(data["id"])
        row.append(data["published"])
        name = affected["package"]["name"]
        row.append(name)

        owner = ""
        repo = ""

        found_github = False
        for reference in data["references"]:
            prefix = "https://github.com/"
            if prefix in reference["url"]:
                new_string = reference["url"][len(prefix):]
                owner = new_string[:new_string.find('/')]
                row.append(owner)
                new_string_2 = new_string[new_string.find('/')+1:]
                repo = new_string_2[:new_string_2.find('/')]
                row.append(repo)
                found_github = True
        if found_github == False:
            row.append("")
            row.append("")
        
        row.append(affected["package"]["purl"])

        if len(data["severity"]) > 0:
            row.append(data["severity"])
        else:
            row.append([])

        if affected["database_specific"] and affected["database_specific"]["categories"]:
            row.append(affected["database_specific"]["categories"])
        else:
            row.append([])

        if len(affected["ranges"]) > 1:
            print("len(affected[\"ranges\"]) > 1")

        introduced = ""
        fixed = ""

        if affected["ranges"] and affected["ranges"][0]["events"] and affected["ranges"][0]["events"]:
            for event in affected["ranges"][0]["events"]:
                if "introduced" in event:
                    introduced = event["introduced"]
                if "fixed" in event:
                    fixed = event["fixed"]
            
        row.append(introduced)
        row.append(fixed)

        #get dependents using crates.io API
        #limitations: only current ones, not historical, must have cargo.toml
        dependents = get_dependents(name)
        row.append(dependents)
        res.append(row)
    
    return res

def process_rustsec_jsons():
    # Folder containing RustSec advisories in the OSV format
    folder_path = './advisory-db-osv/crates/'
    # Read in all vulnerabilities
    first_row = ["id", "published", "name", "gh_owner", "gh_repo", "purl", "severity", "categories", "introduced_version", "patched_version", "dependents"]

    with open('all_vulns_info2.cvs', 'w', newline='') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(first_row)

        for filename in os.listdir(folder_path):
            if filename.endswith('.json'):
                # Construct the full path to the JSON file
                file_path = os.path.join(folder_path, filename)
                # Read the JSON file into a DataFrame
                osv = json_to_row(file_path)
                if osv is not None:
                    for o in osv:
                        print(o)
                    csv_writer.writerows(osv)
    
def get_dependent_patch_info():
    with open('dependent_patch_info.cvs', 'w', newline='') as csv_file:
        csv_writer = csv.writer(csv_file)
        first_row = ["vuln_id", "vuln_package_name", "dependent_name", "dependent_info"]
        csv_writer.writerow(first_row)
        with open('all_vulns_info.cvs', 'r') as csv_file:
            csv_reader = csv.reader(csv_file)
            first = True
            for row in csv_reader:
                if first:
                    first = False
                    continue
                id = row[0]
                package_name = row[2]
                patched_version = row[9]
                introduced_version = row[8]
                if introduced_version[-2:] == '-0':
                    introduced_version = introduced_version[:-2]
                
                dependents = json.loads(row[10].replace("\'", "\""))
                for dependent in dependents:

                    parsed_url = urlparse(dependents[dependent]['github_url'])
                    # Split the path and get the second component (the username)
                    path_components = parsed_url.path.split('/')
                    username = path_components[1] if len(path_components) > 1 else None
                    dependent_on_version = get_version_of_dependency(dependent, dependents[dependent]['version'], package_name)
                    if patched_version == "":
                        #if less than introduced -- this is where tilda and caret matter -- want to get range -- but let's actually just ignore them altogether 
                        if parsing_git_commits.compare_cargo_versions(dependent_on_version, introduced_version) == -1:
                            #dependent on a version that came before the bug was introduced
                            csv_writer.writerow([id, package_name, dependent, {"dependency_patched":False, "dependent_on_vuln_version":False}])
                        else:
                            csv_writer.writerow([id, package_name, dependent, {"dependency_patched":False,  "dependent_on_vuln_version":True}])
                        continue

                    if parsing_git_commits.compare_cargo_versions(dependent_on_version, introduced_version) == -1:
                        #dependent on a version that came before the bug was introduced
                        csv_writer.writerow([id, package_name, dependent, {"dependency_patched":True, "dependent_on_vuln_version":False}])
                    elif parsing_git_commits.compare_cargo_versions(dependent_on_version, patched_version) == -1:
                        #dependent on a version between introduced and fixed
                        csv_writer.writerow([id, package_name, dependent, {"dependency_patched":True, "dependent_on_vuln_version":True}])
                    else:
                        dependent_info = parsing_git_commits.get_info_about_dependency(username, dependent, package_name, patched_version)
                        print([id, package_name, dependent, dependent_info])
                        csv_writer.writerow([id, package_name, dependent, dependent_info])

#process_rustsec_jsons() 
#get_dependent_patch_info()


        
        
