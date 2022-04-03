#!/usr/bin/env python3
""" Generate report for a single cpe from NVD Json files.

This script takes the NVD JSON data feed and collects all data for a given CPE
entry. In generates a markdown file in fvolder out with a table containing the
following information:

- CVE
- Description
- Publish date
- CPE
- Score
- Severity
- Vendor references

and a mermaid gannt chart to show the publish dates.

Parameters are

- the year for which you want to generate the report and
- the cpe you're interested in.

The cpe doesn't need be a complete cpe since it gets compared
via startswith. If it doesn't start with 'cpe:2.3:' this gets added.

If the required nvd data feed is not present it will be downloaded.

Th nvd data feed will be stored in a subfolder './input/' and the resulting
report in a subfolder './output/'.

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.
This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with
this program. If not, see <http://www.gnu.org/licenses/>.
"""

import json
from datetime import datetime
import argparse
import os
import shutil
import requests

parser = argparse.ArgumentParser()

# Adding optional argument
parser.add_argument("-y", "--year", help="The NVDFile", required=True)
parser.add_argument("-c", "--cpe", help="The start of the CPE to search for", required=True)

# Read arguments from command line
args = parser.parse_args()

nvd_year = args.year
nvdfile = f'nvdcve-1.1-{nvd_year}.json'
nvdzip = f'./input/nvdcve-1.1-{nvd_year}.zip'

cpe = args.cpe
if not cpe.startswith('cpe:2.3:'):
    cpe = f'cpe:2.3:{cpe}'

cpe_sw = ' '.join(cpe.split(':')[3:5])
outfilename = f"./output/{'_'.join(cpe.split(':')[3:5])}_{nvd_year}.md"

url = f'https://nvd.nist.gov/feeds/json/cve/1.1/{nvdfile}.zip'

if not os.path.exists('./input'):
    try:
        os.mkdir('./input')
    except OSError:
        print("Can't create ./input")

if not os.path.exists('./output'):
    try:
        os.mkdir('./output')
    except OSError:
        print("Can't create ./output")

if not os.path.exists(f'./input/{nvdfile}'):
    print(f"source file ./input/{nvdfile} can't be found, downloading it")
    # Download from URL
    nvd = requests.get(url)

    # Save to file
    with open(nvdzip, 'wb') as download:
        download.write(nvd.content)

    shutil.unpack_archive(nvdzip, './input')

with open(nvdfile, "r") as nvdcve:
    nvdcvedata = json.load(nvdcve)


nvd_data = []

for item in nvdcvedata['CVE_Items']:
    cve_data = {}
    cve_data['match'] = False
    cve_data['cpe'] = []
    cve_data['ref'] = []
    cve_data['cve'] = item['cve']['CVE_data_meta']['ID']
    cve_data['description'] = item['cve']['description']['description_data'][0]['value']
    cve_data['pubdate'] = datetime.strptime(item['publishedDate'], "%Y-%m-%dT%H:%MZ").strftime('%Y-%m-%d')

    if len(item['impact']) > 0:
        cve_data['cvssvector'] = item['impact']['baseMetricV3']['cvssV3']['vectorString']
        cve_data['score'] = item['impact']['baseMetricV3']['cvssV3']['baseScore']
        cve_data['severity'] = item['impact']['baseMetricV3']['cvssV3']['baseSeverity']
    else:
        cve_data['cvssvector'] = 'N/A'
        cve_data['score'] = 'N/A'
        cve_data['severity'] = 'N/A'

    if len(item['cve']['references']) > 0:
        refs = item['cve']['references']['reference_data']

        if len(refs) > 0:
            for ref in refs:
                if "Vendor Advisory" in ref['tags']:
                    cve_data['ref'].append(ref['url'])

    if len(item['configurations']['nodes']) > 0:
        cpe_match_list = item['configurations']['nodes'][0]['cpe_match']
        for n in range(len(cpe_match_list)):
            cve_data['cpe'].append(cpe_match_list[n]['cpe23Uri'])
            if (cpe_match_list[n]['cpe23Uri']).startswith(cpe):
                cve_data['match'] = True
    nvd_data.append(cve_data)

md_header = f"""
# {cpe_sw} CVE {nvd_year}

## Overview

| CVE | Score | Severity | Description | Published | Affected | References |
| :---: | :---------: | :-------: | :------: | :-----: | :-----:| :----:|
"""

md_gant_header = f"""
## Publish Date

```mermaid
gantt

title {cpe_sw} CVE {nvd_year}
dateFormat YYYY-MM-DD
axisFormat %Y-%m

section CVE Release Dates
"""

with open(outfilename, "w") as outfile:
    outfile.write(md_header)

    for cve_Entry in nvd_data:
        if cve_Entry['match']:
            outfile.write(f"|{cve_Entry['cve']}|{cve_Entry['score']}|{cve_Entry['severity']}| \
                {cve_Entry['description']}|{cve_Entry['pubdate']}|{' '.join(cve_Entry['cpe'])}| \
                    {' '.join(cve_Entry['ref'])} \n")

    outfile.write(md_gant_header)

    num = 0

    for cve_Entry in nvd_data:
        if cve_Entry['match']:
            outfile.write(f" {cve_Entry['cve']}  :cve{num}, {cve_Entry['pubdate']}, 5d\n")
            num = num + 1
    outfile.write("```\n")
