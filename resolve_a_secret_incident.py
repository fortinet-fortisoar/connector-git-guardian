""" Copyright start
Copyright (C) 2008 - 2023 Fortinet Inc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end """
from .make_rest_api_call import MakeRestApiCall


def resolve_a_secret_incident(config: dict, params: dict) -> dict:
    endpoint = f"api.gitguardian.com/v1/incidents/secrets/{params.get('incident_id')}/resolve"
    method = "POST"
    method_data = {"secret_revoked": params.get('secret_revoked')}

    MK = MakeRestApiCall(config=config)
    response = MK.make_request(endpoint=endpoint, method=method, params=params, json_data=method_data)
    return response
