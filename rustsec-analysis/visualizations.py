import pandas as pd

url = 'https://raw.githubusercontent.com/ratoru/cargo-ecosystem-lag/rustsec/rustsec-analysis/all_vulns_info3.cvs'
df = pd.read_csv(url, index_col = 0, on_bad_lines = 'skip')

#time to resolve for packages = date of patch - date of publication
print(df.head(5))
print(df.describe())

#we have 519 vulnerabilities for which data is comprehensive enough
print(df.loc[:, 'severity'])

