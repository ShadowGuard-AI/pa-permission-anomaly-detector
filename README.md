# pa-permission-anomaly-detector
Detects anomalous permission assignments based on historical data. Uses statistical analysis of permission assignments across users and roles to identify outliers. Each user's total permission count, the sum of the lengths of that user's permission strings across all items, is tested against the mean and standard deviation of those totals, and one anomaly is reported per outlying user. - Focused on Tools for analyzing and assessing file system permissions

This tool uses only the Python standard library. No third party packages are required and there is no requirements file.

If the input list is empty or fewer than two users have usable permission data, the run exits 1 with an insufficient data line and writes no report. If the report file resolves to the same path as the data file, the run exits 1 and refuses to overwrite the input. If the report cannot be written, the run exits 1 with a report not saved line.

## Install
`git clone https://github.com/ShadowStrikeHQ/pa-permission-anomaly-detector`

## Usage
`./pa-permission-anomaly-detector [params]`

## Parameters
- `-h`: Show help message and exit
- `--data-file`: Path to the JSON file containing historical permission data.
- `--sensitivity`: No description provided
- `--report-file`: Path to the JSON file where the anomaly report will be saved.

## License
Copyright (c) ShadowStrikeHQ
