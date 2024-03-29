import requests

access_token = ''

#Set up headers with the access token
headers = {
    'Authorization': f'token {access_token}',
    'Accept': 'application/vnd.github.v3+json'
}

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
owner = 'jaredforth'
repo = 'webp'
vulnerable_dependency = 'libwebp-sys'
patched_version = '0.9.3'

# Get all commits from the specified repository
all_commits = get_all_commits(owner, repo)

# Print commit information
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
                        if s in file_info['patch'] and patched_version in file_info['patch']:
                            print("found upgrade to patched version of dependency")
                            print(f"Date: {commit['commit']['author']['date']}")
                            print(f"Message: {commit['commit']['message']}")
                            k = "-" + vulnerable_dependency
                            index_old_version_dependency = file_info['patch'].find(k) + len(k) + 4
                            print('old version of dependency: ')
                            print(file_info['patch'][index_old_version_dependency:index_old_version_dependency+5])
                            
                            p = repo + '\"\n-version'
                            #the same commit diff may include the new version of the dependent
                            if p in file_info['patch']:
                                print("dependent version changed to ")
                                j = "+version = \""
                                index_new_version = file_info['patch'].find(j) + len(j)
                                print(file_info['patch'][index_new_version:index_new_version+5])


#data to collect:
#Cargo.lock - see edits to it 
# https://stackoverflow.com/questions/40393117/getting-file-diff-with-github-api


#goal: CVE->dependents->github of dependent packages/projects->all commits->diff for each commit in cargo.lock file->find package number

#example:
#https://rustsec.org/advisories/RUSTSEC-2023-0061.html 
#https://crates.io/crates/libwebp-sys - vulnerable library
#https://crates.io/crates/webp - dependent
#github of dependent: https://github.com/jaredforth/webp 
