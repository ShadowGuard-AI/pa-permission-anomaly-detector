# pa-permission-anomaly-detector

Detects anomalous permission assignments based on historical data. Uses statistical analysis of permission assignments across users and roles to identify outliers. Each user's total permission count, the sum of the lengths of that user's permission strings across all items, is tested against the mean and standard deviation of those totals, and one anomaly is reported per outlying user. Focused on tools for analyzing and assessing file system permissions.

This tool uses only the Python standard library. No third party packages are required and there is no requirements file.

If the input list is empty or fewer than two users have usable permission data, the run exits 1 with an insufficient data line and writes no report. If the report file resolves to the same path as the data file, the run exits 1 and refuses to overwrite the input. If the report cannot be written, the run exits 1 with a report not saved line.

## Install

```
git clone https://github.com/ShadowGuard-AI/pa-permission-anomaly-detector.git
cd pa-permission-anomaly-detector
```

## Usage

```
python3 main.py --data-file FILE [options]
```

## Parameters

- `--data-file`: Required. Path to the JSON file containing historical permission data. The file must hold a list of objects with `user` and `permissions` fields.
- `--sensitivity`: Sensitivity level (number of standard deviations from the mean), default `2.0`.
- `--report-file`: Path to the JSON file where the anomaly report will be saved, default `anomaly_report.json`.

## Verified in this wave

`python3 main.py --help` exits 0. A sample list of 10 users with a 1 character permission string plus one user with a 50 character string detected exactly 1 anomaly, for that user, with total 50 and deviation 44.55, exit 0. An empty list exits 1 with the insufficient data line, a non-list JSON object exits 1, and no arguments exits 2 with the required `--data-file` error.

## License

See LICENSE.
