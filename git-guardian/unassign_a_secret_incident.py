""" Copyright start
Copyright (C) 2008 - 2023 Fortinet Inc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end """
from .make_rest_api_call import MakeRestApiCall


def unassign_a_secret_incident(config: dict, params: dict) -> dict:
    endpoint = f"v1/incidents/secrets/{params.get('incident_id')}/unassign"
    method = "POST"
    MK = MakeRestApiCall(config=config)
    response = MK.make_request(endpoint=endpoint, method=method, params=params)
    return response