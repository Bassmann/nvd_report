# nvd_report

Generate report for a single cpe from NVD Json files.

This script takes the NVD JSON data feed and collects all data for a given CPE
entry. In generates a markdown file with a table containing the following
information:

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

The cpe doesn't need to be a complete cpe since it gets compared
via `startswith`. If it doesn't start with 'cpe:2.3:' this gets added.

If the required nvd data feed is not present it will be downloaded from [NVD Json Feed](https://nvd.nist.gov/vuln/data-feeds#JSON_FEED)

The nvd data feed will be stored in a subfolder `./input/` and the resulting
report in a subfolder `./output/`.
