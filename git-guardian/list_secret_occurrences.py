""" Copyright start
Copyright (C) 2008 - 2023 Fortinet Inc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end """
from .make_rest_api_call import MakeRestApiCall, build_payload, filter_cursors_from_url


def list_secret_occurrences(config: dict, params: dict) -> dict:
    endpoint = "v1/occurrences/secrets"  # edit endpoint
    method = "GET"  # GET/POST/PUT/DELETE
    filtered_params = build_payload(params)
    MK = MakeRestApiCall(config=config)
    response = MK.make_request(endpoint=endpoint, method=method, params=filtered_params)
    if isinstance(response, dict):
        response = filter_cursors_from_url(response)

    return response
