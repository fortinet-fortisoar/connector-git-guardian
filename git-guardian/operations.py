""" Copyright start
Copyright (C) 2008 - 2023 Fortinet Inc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end """

from connectors.core.connector import get_logger, ConnectorError
from .make_rest_api_call import MakeRestApiCall, build_payload, filter_cursors_from_url
from connectors.cyops_utilities.builtins import upload_file_to_cyops, download_file_from_cyops
from integrations.crudhub import make_request
from os.path import join

logger = get_logger("git-guardian")

VALID_DICT = {"Valid": "valid", "Invalid": "invalid", "Failed to Check": "failed_to_check",
              "No Checker": "no_checker", "Unknown": "unknown", "From Historical Scan": "FROM_HISTORICAL_SCAN",
              "Ignored in Check Run": "IGNORED_IN_CHECK_RUN", "Public": "PUBLIC", "Default Branch" : "DEFAULT_BRANCH",
              "Regression": "REGRESSION", "Sensitive File": "SENSITIVE_FILE", "Test File": "TEST_FILE",
              "No Tags": "NONE", "Critical": "critical", "High": "high", "Medium": "medium", "Low": "low",
              "Info": "info", "Ignored": "IGNORED", "Triggered": "TRIGGERED",
              "Assigned": "ASSIGNED", "Resolved": "RESOLVED", "Date (Ascending)": "date", "Date (Descending)": "-date",
              "Resolved At (Ascending)": "resolved_at", "Resolved At (Descending)": "-resolved_at",
              "Ignored At (Ascending)": "ignored_at", "Ignored At (Descending)": "-ignored_at"}

list_sources_dict = {"Last Scan Date (Ascending)": "last_scan_date", "Last Scan Date (Descending)": "-last_scan_date",
                     "Pending": "pending", "Running": "running", "Canceled": "canceled", "Failed": "failed", "Too Large": "too_large",
                     "Timeout": "timeout", "Finished": "finished", "Safe": "safe", "Unknown": "unknown", "At Risk": "at_risk",
                     "Bitbucket": "bitbucket", "Github": "github", "Gitlab": "gitlab", "Azure Devops": "azure_devops", "Public": "public",
                     "Private": "private", "Internal": "internal"}


def list_secret_incidents(config: dict, params: dict) -> dict:
    try:
        endpoint = "v1/incidents/secrets"
        method = "GET"
        filtered_params = build_payload(params)
        params_check = ["status", "severity", "validity", "ordering"]
        for p in params_check:
            if filtered_params.get(p) is not None:
                filtered_params.update({f"{p}": VALID_DICT.get(filtered_params.get(p))})

        if filtered_params.get("tags") is not None:
            result_list = [VALID_DICT.get(x) for x in filtered_params.get("tags")]
            resultString = ','.join(result_list)
            filtered_params.update({"tags": resultString})

        if filtered_params.get('per_page') is not None:
            per_page = filtered_params.get('per_page')
            if type(per_page) is str:
                raise Exception("Number of Incidents per page can't be a String")

            if per_page <= 0:
                raise Exception("Number of Incidents can't be Negative or Zero")

        MK = MakeRestApiCall(config=config)
        response = MK.make_request(endpoint=endpoint, method=method, params=filtered_params)
        if isinstance(response, dict):
            response = filter_cursors_from_url(response)

        return response

    except Exception as err:
        logger.error(f"Error occurred in List Secret Incidents{err}")
        raise ConnectorError(err)


def retrieve_a_secret_incident(config: dict, params: dict) -> dict:
    try:
        endpoint = f"v1/incidents/secrets/{params.get('incident_id')}"
        method = "GET"
        filtered_params = build_payload(params)

        MK = MakeRestApiCall(config=config)
        response = MK.make_request(endpoint=endpoint, method=method, params=filtered_params)
        return response
    except Exception as err:
        logger.error(f"Error Occurred in Retrieve a Secret Incident {err}")
        raise ConnectorError(err)


def assign_a_secret_incident(config: dict, params: dict) -> dict:
    try:
        endpoint = f"v1/incidents/secrets/{params.get('incident_id')}/assign"
        method = "POST"
        filtered_params = build_payload(params)
        MK = MakeRestApiCall(config=config)
        response = MK.make_request(endpoint=endpoint, method=method,
                                   json_data=filtered_params)
        return response
    except Exception as err:
        logger.error(f"Error Occurred in Assign a Secret Incident {err}")
        raise ConnectorError(err)


def content_scan(config: dict, params: dict) -> dict:
    try:
        endpoint = "v1/scan"
        method = "POST"

        file_iri = _handle_params(params)
        files = _submitFile(file_iri)

        method_data = {"document": files.get("document"), "filename": params.get('filename')}
        method_header = {"Content-Type": "application/json"}
        logger.info(method_data.get('document'))

        MK = MakeRestApiCall(config=config)
        response = MK.make_request(endpoint=endpoint, method=method, params=params, headers=method_header,
                                   json_data=method_data)
        return response
    except Exception as err:
        logger.error(f"Error Occurred in method Content Scan {err}")
        raise ConnectorError(err)


def update_a_secret_incident(config: dict, params: dict) -> dict:
    try:
        endpoint = f"v1/incidents/secrets/{params.get('incident_id')}"
        method = "PATCH"
        method_data = {"severity": params.get('severity').lower()}

        MK = MakeRestApiCall(config=config)
        response = MK.make_request(endpoint=endpoint, method=method, params=params,
                                   json_data=method_data)
        return response
    except Exception as err:
        logger.error(f"Error Occurred in Update a Secret Incident {err}")
        raise ConnectorError(err)


def unassign_a_secret_incident(config: dict, params: dict) -> dict:
    try:
        endpoint = f"v1/incidents/secrets/{params.get('incident_id')}/unassign"
        method = "POST"
        MK = MakeRestApiCall(config=config)
        response = MK.make_request(endpoint=endpoint, method=method, params=params)
        return response
    except Exception as err:
        logger.error(f"Error Occurred in Unassign a Secret Incident {err}")
        raise ConnectorError(err)


def resolve_a_secret_incident(config: dict, params: dict) -> dict:
    try:
        endpoint = f"v1/incidents/secrets/{params.get('incident_id')}/resolve"
        method = "POST"
        method_data = {"secret_revoked": params.get('secret_revoked')}

        MK = MakeRestApiCall(config=config)
        response = MK.make_request(endpoint=endpoint, method=method, params=params, json_data=method_data)
        return response
    except Exception as err:
        logger.error(f"Error Occurred in Resolve a Secret Incident {err}")
        raise ConnectorError(err)


def list_secret_occurrences(config: dict, params: dict) -> dict:
    try:
        endpoint = "v1/occurrences/secrets"
        method = "GET"
        filtered_params = build_payload(params)

        if filtered_params.get("tags") is not None:
            result_list = [VALID_DICT.get(x) for x in filtered_params.get("tags")]
            resultString = ','.join(result_list)
            filtered_params.update({"tags": resultString})

        if filtered_params.get('per_page') is not None:
            per_page = filtered_params.get('per_page')
            if type(per_page) is str:
                raise Exception("Number of Occurrences per page can't be a String")

            if per_page <= 0:
                raise Exception("Number of Occurrences can't be Negative or Zero")

        MK = MakeRestApiCall(config=config)
        response = MK.make_request(endpoint=endpoint, method=method, params=filtered_params)

        if isinstance(response, dict):
            response = filter_cursors_from_url(response)

        return response
    except Exception as err:
        logger.error(f"Error Occurred in List secret Occurrences {err}")
        raise ConnectorError(err)


def get_members_list(config: dict, params: dict) -> dict:
    try:
        endpoint = "v1/members"
        method = "GET"
        MK = MakeRestApiCall(config=config)
        response = MK.make_request(endpoint=endpoint, method=method)

        return response
    except Exception as err:
        logger.error(f"Error Occurred in Get Members List {err}")
        raise ConnectorError(err)


def list_sources(config: dict, params: dict) -> dict:
    try:
        endpoint = "v1/sources"
        method = "GET"
        filtered_params = build_payload(params)
        params_check = ["last_scan_status", "health", "type", "ordering", "visibility"]
        for p in params_check:
            if filtered_params.get(p) is not None:
                filtered_params.update({f"{p}": list_sources_dict.get(filtered_params.get(p))})

        if filtered_params.get('per_page') is not None:
            per_page = filtered_params.get('per_page')
            if type(per_page) is str:
                raise Exception("Number of Sources per page can't be a String")

            if per_page <= 0:
                raise Exception("Number of Sources can't be Negative or Zero")

        MK = MakeRestApiCall(config=config)
        response = MK.make_request(endpoint=endpoint, method=method, params=filtered_params)

        if isinstance(response, dict):
            response = filter_cursors_from_url(response)

        return response

    except Exception as err:
        logger.error(f"Error Occurred in List Sources {err}")
        raise ConnectorError(err)


def _handle_params(params):
    value = str(params.get('value'))
    input_type = params.get('input')
    try:
        if isinstance(value, bytes):
            value = value.decode('utf-8')
        if input_type == 'Attachment ID':
            if not value.startswith('/api/3/attachments/'):
                value = '/api/3/attachments/{0}'.format(value)
            attachment_data = make_request(value, 'GET')
            file_iri = attachment_data['file']['@id']
            file_name = attachment_data['file']['filename']
            return file_iri
        elif input_type == 'File IRI':
            if value.startswith('/api/3/files/'):
                return value
            else:
                raise ConnectorError('Invalid File IRI {0}'.format(value))
    except Exception as err:
        raise ConnectorError('Requested resource could not be found with input type "{0}" and value "{1}"'.format
                             (input_type, value.replace('/api/3/attachments/', '')))


def _submitFile(file_iri):
    try:
        file_path = join('/tmp', download_file_from_cyops(file_iri)['cyops_file_path'])
        with open(file_path, 'rb') as attachment:
            file_data = attachment.read()
        if file_data:
            files = {"document": file_data}
            return files
        raise ConnectorError('File size too large, submit file up to 32 MB')
    except Exception as Err:
        raise ConnectorError('Error in submitFile(): %s' % Err)


operations = {
    "list_secret_incidents": list_secret_incidents,
    "retrieve_a_secret_incident": retrieve_a_secret_incident,
    "update_a_secret_incident": update_a_secret_incident,
    "assign_a_secret_incident": assign_a_secret_incident,
    "unassign_a_secret_incident": unassign_a_secret_incident,
    "resolve_a_secret_incident": resolve_a_secret_incident,
    "content_scan": content_scan,
    "list_secret_occurrences": list_secret_occurrences,
    "get_members_list": get_members_list,
    "list_sources": list_sources
}
