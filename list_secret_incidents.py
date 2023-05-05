""" Copyright start
Copyright (C) 2008 - 2023 Fortinet Inc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end """
from .make_rest_api_call import MakeRestApiCall, build_payload

valid_dict = {"Valid": "valid", "Invalid": "invalid", "Failed to Check": "failed_to_check",
              "No Checker": "no_checker", "Unknown": "unknown", "From Historical Scan": "FROM_HISTORICAL_SCAN",
              "Ignored in Check Run": "IGNORED_IN_CHECK_RUN", "Public": "PUBLIC",
              "Regression": "REGRESSION", "Sensitive File": "SENSITIVE_FILE", "Test File": "TEST_FILE",
              "None": "NONE", "Critical": "critical", "High": "high", "Medium": "medium", "Low": "low",
              "Info": "info", "Unknown": "unknown", "Ignored": "IGNORED", "Triggered": "TRIGGERED",
              "Assigned": "ASSIGNED", "Resolved": "RESOLVED", "Date (Ascending)": "date", "Date (Descending)": "-date",
              "Resolved At (Ascending)": "resolved_at", "Resolved At (Descending)": "-resolved_at",
              "Ignored At (Ascending)": "ignored_at", "Ignored At (Descending)": "-ignored_at"}

def list_secret_incidents(config: dict, params: dict) -> dict:
    endpoint = "api.gitguardian.com/v1/incidents/secrets"
    method = "GET"
    filtered_params = build_payload(params)
    params_check = ["status", "severity", "validity", "ordering"]

    for p in params_check:
        if filtered_params.get(p) is not None:
            filtered_params.update({f"{p}": valid_dict.get(filtered_params.get(p))})

    if filtered_params.get("tags") is not None:
        result_list = [valid_dict.get(x) for x in filtered_params.get("tags")]
        resultString = ','.join(result_list)
        filtered_params.update({"tags": resultString})

    MK = MakeRestApiCall(config=config)
    response = MK.make_request(endpoint=endpoint, method=method, params=filtered_params)
    return response
