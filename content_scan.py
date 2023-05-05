""" Copyright start
Copyright (C) 2008 - 2023 Fortinet Inc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end """
from .make_rest_api_call import MakeRestApiCall, build_payload


def content_scan(config: dict, params: dict) -> dict:
    endpoint = "api.gitguardian.com/v1/scan"
    method = "POST"
    filtered_params = build_payload(params)

    method_header = {"Content-Type": "application/json"}

    MK = MakeRestApiCall(config=config)
    response = MK.make_request(endpoint=endpoint, method=method, params=params, headers=method_header, json_data=filtered_params)
    return response