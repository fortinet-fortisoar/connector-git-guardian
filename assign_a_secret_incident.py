""" Copyright start
Copyright (C) 2008 - 2023 Fortinet Inc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end """
from .make_rest_api_call import MakeRestApiCall, build_payload

def assign_a_secret_incident(config: dict, params: dict) -> dict:
    endpoint = f"api.gitguardian.com/v1/incidents/secrets/{params.get('incident_id')}/assign"
    method = "POST"
    filtered_params = build_payload(params)
    MK = MakeRestApiCall(config=config)
    response = MK.make_request(endpoint=endpoint, method=method,
                               json_data=filtered_params)
    return response
