""" Copyright start
Copyright (C) 2008 - 2023 Fortinet Inc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end """
from .make_rest_api_call import MakeRestApiCall, build_payload
from connectors.core.connector import get_logger, ConnectorError
from connectors.cyops_utilities.builtins import upload_file_to_cyops, download_file_from_cyops
from integrations.crudhub import make_request
from os.path import join


def handle_params(params):
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


def submitFile(file_iri):
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

def content_scan(config: dict, params: dict) -> dict:
    endpoint = "v1/scan"
    method = "POST"

    file_iri = handle_params(params)
    files = submitFile(file_iri)

    method_data = {"document": files.get("document")}
    method_header = {"Content-Type": "application/json"}

    MK = MakeRestApiCall(config=config)
    response = MK.make_request(endpoint=endpoint, method=method, params=params, headers=method_header, json_data=method_data)
    return response