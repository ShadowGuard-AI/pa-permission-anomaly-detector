import argparse
import logging
import os
import sys
import json
from typing import List, Dict, Any
import statistics

# Constants
LOG_FILE = "pa_permission_anomaly_detector.log"
DEFAULT_SENSITIVITY = 2.0  # Standard deviations for anomaly detection


# Setup logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse() -> argparse.ArgumentParser:
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description="Detects anomalous permission assignments based on historical data."
    )
    parser.add_argument(
        "--data-file",
        type=str,
        required=True,
        help="Path to the JSON file containing historical permission data.",
    )
    parser.add_argument(
        "--sensitivity",
        type=float,
        default=DEFAULT_SENSITIVITY,
        help=f"Sensitivity level (number of standard deviations from the mean). Default: {DEFAULT_SENSITIVITY}",
    )
    parser.add_argument(
        "--report-file",
        type=str,
        default="anomaly_report.json",
        help="Path to the JSON file where the anomaly report will be saved.",
    )

    return parser


def load_permission_data(data_file: str) -> List[Dict[str, Any]]:
    """
    Loads permission data from a JSON file.

    Args:
        data_file (str): The path to the JSON data file.

    Returns:
        List[Dict[str, Any]]: A list of permission data dictionaries.

    Raises:
        FileNotFoundError: If the data file does not exist.
        json.JSONDecodeError: If the data file is not a valid JSON file.
        ValueError: If the data file doesn't contain a list of dictionaries.
    """
    try:
        with open(data_file, "r") as f:
            data = json.load(f)

        if not isinstance(data, list):
            raise ValueError("The data file must contain a list of dictionaries.")

        for item in data:
            if not isinstance(item, dict):
                raise ValueError("The data file must contain a list of dictionaries.")
        return data
    except FileNotFoundError:
        logging.error(f"Data file not found: {data_file}")
        raise
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON data: {e}")
        raise
    except ValueError as e:
        logging.error(f"Invalid data format: {e}")
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        raise


def analyze_permissions(data: List[Dict[str, Any]], sensitivity: float) -> List[Dict[str, Any]]:
    """
    Analyzes permission data to identify anomalies based on historical data.

    Args:
        data (List[Dict[str, Any]]): A list of permission data dictionaries.
          Each dictionary should contain keys like 'user', 'role', 'file', and 'permissions'.
        sensitivity (float): The sensitivity level (number of standard deviations).

    Returns:
        List[Dict[str, Any]]: A list of dictionaries representing detected anomalies.
    """
    anomalies = []

    # Collect statistics on permission assignments. Each user's total is
    # the sum of the lengths of that user's permission strings across
    # all of that user's items.
    user_permission_counts = {}
    for item in data:
        user = item.get("user")
        permissions = item.get("permissions") # Example: "rwx" for read, write, execute
        if user and permissions:
            if user not in user_permission_counts:
                user_permission_counts[user] = 0
            user_permission_counts[user] += len(permissions)

    # Calculate the mean and standard deviation of the per user totals.
    if not user_permission_counts:
        logging.warning("No permission data available for analysis.")
        return anomalies #Return empty list

    counts = list(user_permission_counts.values())

    if len(counts) < 2:  # Need at least two data points to calculate stddev
        logging.warning("Insufficient data to calculate standard deviation.")
        return anomalies # Return empty list if there's not enough data

    mean = statistics.mean(counts)
    stdev = statistics.stdev(counts) if len(counts) > 1 else 0 # Prevent error when only one sample


    # Identify users whose total count is an outlier against the totals
    # themselves. One anomaly is emitted per outlying user.
    for user, total_count in user_permission_counts.items():
        if stdev > 0 and (abs(total_count - mean) > sensitivity * stdev):
            anomalies.append({
                "user": user,
                "total_permission_count": total_count,
                "deviation": total_count - mean,
                "message": f"Anomalous permission total for user {user}: {total_count} (deviation from mean: {total_count - mean:.2f})",
            })
            logging.warning(f"Detected anomaly: User {user} - total {total_count}")

    return anomalies


def save_report(report: List[Dict[str, Any]], report_file: str) -> bool:
    """
    Saves the anomaly report to a JSON file.

    Args:
        report (List[Dict[str, Any]]): A list of anomaly dictionaries.
        report_file (str): The path to the output JSON file.

    Returns:
        bool: True when the report was written, False otherwise.
    """
    try:
        with open(report_file, "w") as f:
            json.dump(report, f, indent=4)
        logging.info(f"Anomaly report saved to: {report_file}")
        return True
    except Exception as e:
        logging.error(f"Error saving report: {e}")
        print(f"Error saving report: {e}", file=sys.stderr)
        return False


def main():
    """
    Main entry point of the pa-permission-anomaly-detector tool.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    try:
        # Input Validation
        if not os.path.exists(args.data_file):
            raise FileNotFoundError(f"Data file not found: {args.data_file}")

        if args.sensitivity <= 0:
            raise ValueError("Sensitivity must be a positive number.")

        if os.path.realpath(args.data_file) == os.path.realpath(args.report_file):
            print("Error: Report file must not be the same as the data file.", file=sys.stderr)
            sys.exit(1)

        data = load_permission_data(args.data_file)

        usable_users = {item.get("user") for item in data if item.get("user") and item.get("permissions")}
        if not data or len(usable_users) < 2:
            print("Insufficient data: need at least two users with permission data to detect anomalies.", file=sys.stderr)
            sys.exit(1)

        anomalies = analyze_permissions(data, args.sensitivity)
        if not save_report(anomalies, args.report_file):
            print(f"Report not saved: {args.report_file}", file=sys.stderr)
            sys.exit(1)

        if anomalies:
            print(f"Detected {len(anomalies)} anomalies.  See report file: {args.report_file}")
        else:
            print("No anomalies detected.")
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON data - {e}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        logging.exception("An unexpected error occurred.")
        sys.exit(1)

if __name__ == "__main__":
    main()