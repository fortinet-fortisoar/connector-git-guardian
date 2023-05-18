""" Copyright start
Copyright (C) 2008 - 2023 Fortinet Inc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end """
from .make_rest_api_call import MakeRestApiCall

def _check_health(config: dict) -> bool:
    try:
        endpoint = "v1/incidents/secrets"
        method = "GET"
        api_token = f"Token {config.get('api_key')}"
        method_header = {"Authorization": api_token}
        MS = MakeRestApiCall(config=config)
        MS.make_request(endpoint=endpoint, method=method, headers=method_header)
        return True
    except Exception as e:
        raise Exception(e)
