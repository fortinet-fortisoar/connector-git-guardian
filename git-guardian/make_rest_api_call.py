""" Copyright start
Copyright (C) 2008 - 2023 Fortinet Inc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end """
import requests
import time
from urllib.parse import urlparse, parse_qs
from connectors.core.connector import get_logger, ConnectorError
from connectors.core.utils import update_connnector_config

error_msg = {
    401: 'Authentication failed due to invalid credentials',
    429: 'Rate limit was exceeded',
    403: 'Token is invalid or expired',
    "ssl_error": 'SSL certificate validation failed',
    'time_out': 'The request timed out while trying to connect to the remote server',
}

logger = get_logger("gitguardian")


def build_payload(params):
    return {key: val for key, val in params.items() if val is not None and val != ''}

def filter_cursors_from_url(res):
    if res.get('links').get('next') is not None:
        parsed_url = urlparse(res.get('links').get('next').get('url'))
        query_params = parse_qs(parsed_url.query)
        res.update({"next_cursor": query_params.get("cursor")[0]})
    if res.get('links').get('prev') is not None:
        parsed_url = urlparse(res.get('links').get('prev').get('url'))
        query_params = parse_qs(parsed_url.query)
        res.update({"prev_cursor": query_params.get("cursor")[0]})
    res.pop('links')
    return res


class MakeRestApiCall:

    def __init__(self, config):
        self.server_url = "https://api.gitguardian.com/"
        self.verify_ssl = config.get("verify_ssl", True)
        self.method_header = {"Authorization": f"Token {config.get('api_key')}"}

    def make_request(self, endpoint='', params=None, data=None, method='GET', headers=None, url=None, json_data=None):
        try:
            if url is None:
                url = self.server_url + endpoint
            if headers is not None:
                self.method_header.update(headers)
            response = requests.request(method=method, url=url,
                                        headers=self.method_header, data=data, json=json_data, params=params,
                                        verify=self.verify_ssl)

            if response.ok:
                if 'json' in str(response.headers):
                    if response.links != {}:
                        return {"result": response.json(), "links": response.links}
                    else:
                        return response.json()
                else:
                    return response.text
            else:
                logger.error("Error: {0}".format(response.json()))
                raise ConnectorError('{0}'.format(error_msg.get(response.status_code, response.text)))
        except requests.exceptions.SSLError as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(error_msg.get('ssl_error')))
        except requests.exceptions.ConnectionError as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(error_msg.get('time_out')))
        except Exception as e:
            logger.error('{0}'.format(e))
            raise ConnectorError('{0}'.format(e))
