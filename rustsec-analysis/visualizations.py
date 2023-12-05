import pandas as pd
import matplotlib.pyplot as plt
import json
from cvss import CVSS2, CVSS3
import numpy as np
import seaborn as sb
from datetime import datetime, timezone, timedelta


url = 'https://raw.githubusercontent.com/ratoru/cargo-ecosystem-lag/rustsec/rustsec-analysis/all_vulns_info5.cvs'
df = pd.read_csv(url, index_col = 0, on_bad_lines = 'skip')
#id,published,name,gh_owner,gh_repo,purl,severity,categories_vuln,categories_package,github_link,introduced_version,patched_version,date_of_patch,dependents


#time to resolve for packages = date of patch - date of publication
print(df.head(5))
print(df.describe())

#we have 519 vulnerabilities for which data is comprehensive enough
print(df.loc[:, 'severity'])
print(df.loc[:, 'categories_vuln'])



severity_score = []

for string_data in df.loc[:, 'severity']:
    if len(string_data) > 10:
        end = len(string_data) - 3
        c = CVSS3(string_data[31:end])
        c.clean_vector()
        severity_score.append(sum(c.scores()))
    else: 
        severity_score.append(0)


df.insert(2, "numeric_severity", severity_score, True)
data = df[(df['numeric_severity'] != 0)]
plt.figure(figsize = (5,5))
sb.kdeplot(data , bw = 0.5 , fill = True).set(title='Density Plot of Severity Score', xlabel='Severity Scores', ylabel='Density')
plt.show()
plt.clf()
plt.cla()
plt.close()



'''
for string_data in df.loc[:, 'categories_vuln']:
    print(type(string_data))
    print(string_data)
    if len(string_data) > 10:
        end = len(string_data) - 3
        c = CVSS3(string_data[31:end])
        c.clean_vector()
        severity_score.append(sum(c.scores()))
    else: 
        severity_score.append(0)

df_expanded = df.explode('categories_vulns')

# Create a boxplot using seaborn
plt.figure(figsize=(10, 6))
sns.boxplot(x='categories_vulns', y='numeric_severity', data=df_expanded)
plt.title('Boxplot of Numeric Severity by Categories Vulns')
plt.xlabel('Categories Vulns')
plt.ylabel('Numeric Severity')
plt.show()
'''

#returns the difference between two dates.
def compare_date_strings(date_published, date_patch):
    format_str = '%Y-%m-%dT%H:%M:%SZ'
    
    # Convert date strings to datetime objects
    date1 = datetime.strptime(date_published, format_str)
    date2 = datetime.strptime(date_patch, format_str)

    # Perform the comparison
    td =  date2 - date1
    return td.days
#time to resolve vs. severity
time_to_resolve = []

for index, row in df.iterrows():
    date_published = row['published']
    date_patch = str(row['date_of_patch'])
    
    if date_patch != 'nan':
        time_to_resolve.append(compare_date_strings(date_published, date_patch))
    else:
        time_to_resolve.append(-1)

df.insert(3, "time_resolve", time_to_resolve, True)

#Generating data.

data = df.loc[:, 'time_resolve'] >= 0
plt.figure(figsize = (5,5))
sb.kdeplot(data , bw = 0.5 , fill = True).set(title='Density Plot of Time to Resolve', xlabel='Time to Resolve in Days', ylabel='Density')
plt.show()
plt.clf()
plt.cla()
plt.close()


filtered_df = df[(df['numeric_severity'] != 0) & (df['time_resolve'] >= 0)]
# Scatter plot
plt.scatter(filtered_df['numeric_severity'], filtered_df['time_resolve'])
# Set plot labels and title
plt.xlabel('Severity')
plt.ylabel('Time to Resolve in Days')
plt.title('Scatter Plot: Severity vs Time to Resolve')

# Show the plot
plt.show()
plt.clf()
plt.cla()
plt.close()


