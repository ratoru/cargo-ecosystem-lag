import requests
import datetime

access_token = ''

#Set up headers with the access token
headers = {
    'Authorization': f'token {access_token}',
    'Accept': 'application/vnd.github.v3+json'
}

def compare_cargo_versions(A, B):
    """
        A (str): The first version number as a string.
        B (str): The second version number as a string.
    Returns:
        int: -1 if version A comes before version B, 0 if they're equal, and 1 if version A comes after version B.
    """
    version_A = list(map(int, A.split('.')))
    version_B = list(map(int, B.split('.')))

    # Compare each component of the version
    for a, b in zip(version_A, version_B):
        if a < b:
            return -1
        elif a > b:
            return 1
    return 0

#returns -1 if date1 came before date2, 0 if theyre the same, 1 if date1 came after date2
def compare_date_strings(date1, date2):
    format_str = '%Y-%m-%dT%H:%M:%SZ'
    
    # Convert date strings to datetime objects
    date1 = datetime.strptime(date_str1, format_str)
    date2 = datetime.strptime(date_str2, format_str)

    # Perform the comparison
    if date1 < date2:
        return -1
    elif date1 == date2:
        return 0
    else:
        return 1

def get_all_commits(owner, repo):
    # Define the API endpoint
    url = f'https://api.github.com/repos/{owner}/{repo}/commits'

    # Make the GET request
    response = requests.get(url, headers=headers)

    # Check the status code
    if response.status_code == 200:
        # Successful request
        commits = response.json()
        return commits
    else:
        # Error handling
        print(f"Error: {response.status_code}")
        print(response.text)
        return None
    
def get_commit_details(commit_url):
    # Set up headers with the access token

    # Make the GET request to the commit URL
    response = requests.get(commit_url, headers=headers)

    # Check the status code
    if response.status_code == 200:
        # Successful request
        commit_details = response.json()
        return commit_details
    else:
        # Error handling
        print(f"Error: {response.status_code}")
        print(response.text)
        return None

# Replace these with your own values
owner = 'jaredforth' #'libwebp-sys'
repo = 'webp' #NoXF
vulnerable_dependency = 'libwebp-sys'
patched_version = '0.9.3'

#return object {"found_patch": T/F, "dependency_version_old": , "dependency_version_new": , "new_version": , "time_upgrade": , "commit_msg" }
def get_info_about_dependency(owner, repo, vulnerable_dependency, patched_version):
    # Get all commits from the specified repository
    all_commits = get_all_commits(owner, repo)

    # Print commit information
    res = {"found_patch":False}
    
    if all_commits:
        for commit in all_commits:
            # print(f"Commit SHA: {commit['sha']}")
            # print(f"Author: {commit['commit']['author']['name']}")
            # print('-' * 50)

            commit_details = get_commit_details(commit['url'])

            files_affected = commit_details['files']
            if files_affected:
                for file_info in files_affected:
                    if file_info['filename'] == 'Cargo.toml':
                        if 'patch' in file_info:
                            s = "+" + vulnerable_dependency
                            if s in file_info['patch']:
                                index_dependency = file_info['patch'].find(s)
                                
                                substr = file_info['patch'][index_dependency+len(vulnerable_dependency)+4:]
                                dependency_version = (substr[:substr.find('\n')]).strip('\"')

                                if compare_cargo_versions(dependency_version, patched_version) >= 0:
                                    
                                    #print("found upgrade to patched version of dependency")
                                    res["found_patch"] = True

                                    #if we've captured a commit already, continue if this date came after the one we have. otherwise, override old info.
                                    if res["time_upgrade"] != None and compare_date_strings(commit['commit']['author']['date'], res["time_upgrade"]) > -1:
                                        break

                                    res["time_upgrade"] = commit['commit']['author']['date']
                                    res["commit_msg"] = commit['commit']['message']
                                    res["dependency_version_new"] = dependency_version

                                    # print(f"Date: {commit['commit']['author']['date']}")
                                    # print(f"Message: {commit['commit']['message']}")
                                    k = "-" + vulnerable_dependency
                                    index_old_version_dependency = file_info['patch'].find(k) + len(k) + 4
                                    #print('old version of dependency: ')
                                    res["dependency_version_old"] = file_info['patch'][index_old_version_dependency:index_old_version_dependency+5]
                                    #print(file_info['patch'][index_old_version_dependency:index_old_version_dependency+5])
                                    
                                    p = repo + '\"\n-version'
                                    #the same commit diff may include the new version of the dependent
                                    if p in file_info['patch']:
                                        #print("dependent version changed to ")
                                        j = "+version = \""
                                        index_new_version = file_info['patch'].find(j) + len(j)
                                        res["new_version"] = file_info['patch'][index_new_version:index_new_version+5]
                                        #print(file_info['patch'][index_new_version:index_new_version+5])
        
    return res

#get_info_about_dependency(owner, repo, vulnerable_dependency, patched_version)

#data to collect:
#Cargo.lock - see edits to it 
# https://stackoverflow.com/questions/40393117/getting-file-diff-with-github-api


#goal: CVE->dependents->github of dependent packages/projects->all commits->diff for each commit in cargo.lock file->find package number

#example:
#https://rustsec.org/advisories/RUSTSEC-2023-0061.html 
#https://crates.io/crates/libwebp-sys - vulnerable library
#https://crates.io/crates/webp - dependent
#github of dependent: https://github.com/jaredforth/webp 



#check for multiple branches -- actually just take first edit
#if a dependent appears not to be patched, it could be because it was using a version less than the "introduced" version