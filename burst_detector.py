
from datetime import datetime, timedelta


# Function to detect unusual bursts of failed login attempts
def detect_bursts(records, threshold=5, window_minutes=2):

    # Store failed login records by username
    user_attempts = {}

    # Step 1: Filter failed login attempts
    for record in records:

        if record["status"].upper() == "FAILED":

            username = record["username"]

            timestamp = datetime.strptime(
                record["timestamp"],
                "%Y-%m-%d %H:%M:%S"
            )

            if username not in user_attempts:
                user_attempts[username] = []

            user_attempts[username].append(timestamp)

    # Step 2: Detect bursts
    alerts = []

    time_window = timedelta(minutes=window_minutes)

    for username, timestamps in user_attempts.items():

        # Arrange timestamps in chronological order
        timestamps.sort()

        left = 0

        for right in range(len(timestamps)):

            # Remove attempts outside the time window
            while timestamps[right] - timestamps[left] > time_window:
                left += 1

            # Count attempts inside the time window
            count = right - left + 1

            # Check whether threshold is reached
            if count >= threshold:

                alert = {
                    "username": username,
                    "failed_attempts": count,
                    "start_time": timestamps[left],
                    "end_time": timestamps[right],
                    "message": "Unusual burst of failed logins detected"
                }

                # Avoid duplicate alerts for the same burst
                if not alerts or not any(
                    a["username"] == username
                    and a["end_time"] == timestamps[right]
                    for a in alerts
                ):
                    alerts.append(alert)

    return alerts


# Main program
if __name__ == "__main__":

    # Sample fictional login records
    records = [
        {
            "timestamp": "2026-11-20 09:00:00",
            "username": "student01",
            "status": "FAILED"
        },
        {
            "timestamp": "2026-11-20 09:00:30",
            "username": "student01",
            "status": "FAILED"
        },
        {
            "timestamp": "2026-11-20 09:01:00",
            "username": "student01",
            "status": "FAILED"
        },
        {
            "timestamp": "2026-11-20 09:01:30",
            "username": "student01",
            "status": "FAILED"
        },
        {
            "timestamp": "2026-11-20 09:02:00",
            "username": "student01",
            "status": "FAILED"
        },
        {
            "timestamp": "2026-11-20 09:03:00",
            "username": "student02",
            "status": "SUCCESS"
        }
    ]

    # Call burst detection function
    results = detect_bursts(
        records,
        threshold=5,
        window_minutes=2
    )

    # Display results
    print("\n===== BURST DETECTION REPORT =====")

    if results:
        for alert in results:

            print("\nUsername:", alert["username"])
            print("Failed Attempts:", alert["failed_attempts"])
            print("Start Time:", alert["start_time"])
            print("End Time:", alert["end_time"])
            print("Alert:", alert["message"])

    else:
        print("No unusual login bursts detected.")

