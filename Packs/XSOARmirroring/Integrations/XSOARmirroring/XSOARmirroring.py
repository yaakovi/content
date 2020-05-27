import demistomock as demisto
from CommonServerPython import *

import traceback
from typing import Any, Dict, List, Optional, Tuple, cast

import dateparser

''' CONSTANTS '''


MAX_INCIDENTS_TO_FETCH = 100


''' CLIENT CLASS '''


class Client(BaseClient):
    def search_incidents(self, query: Optional[str], max_results: Optional[int],
                         start_time: Optional[int]) -> List[Dict[str, Any]]:
        data = {
            'filter': {
                'query': query,
                'size': max_results or 10,
                'fromDate': timestamp_to_datestring(start_time)
            }
        }
        return self._http_request(
            method='POST',
            url_suffix=f'/incidents/search',
            json_data=data
        ).get('data')

    def get_incident(self, incident_id: str) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=f'/incident/load/{incident_id}'
        )

    def get_incident_entries(self, incident_id: str, from_date: Optional[int], max_results: Optional[int],
                             categories: Optional[List[str]], tags: Optional[List[str]]) -> List[Dict[str, Any]]:
        data = {
            'pageSize': max_results or 50,
            'fromTime': timestamp_to_datestring(from_date),
            'categories': categories,
            'tags': tags
        }
        inv_with_entries = self._http_request(
            method='POST',
            url_suffix=f'/investigation/{incident_id}',
            json_data=data
        )
        return inv_with_entries.get('entries')

    def get_incident_fields(self) -> List[Dict[str, Any]]:
        return self._http_request(
            method='GET',
            url_suffix=f'/incidentfields'
        )

    def update_incident(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix='/incident',
            json_data=incident
        )

    def add_incident_entry(self, incident_id: Optional[str], entry: Dict[str, Any]) -> Dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix='/entry/formatted',
            json_data={
                'contents': entry.get('contents'),
                'format': entry.get('format'),
                'investigationId': incident_id
            }
            # TODO - add tags, note, etc.
        )


''' HELPER FUNCTIONS '''


def arg_to_int(arg: Any, arg_name: str, required: bool = False) -> Optional[int]:
    """Converts an XSOAR argument to a Python int

    This function is used to quickly validate an argument provided to XSOAR
    via ``demisto.args()`` into an ``int`` type. It will throw a ValueError
    if the input is invalid. If the input is None, it will throw a ValueError
    if required is ``True``, or ``None`` if required is ``False.

    :type arg: ``Any``
    :param arg: argument to convert

    :type arg_name: ``str``
    :param arg_name: argument name

    :type required: ``bool``
    :param required:
        throws exception if ``True`` and argument provided is None

    :return:
        returns an ``int`` if arg can be converted
        returns ``None`` if arg is ``None`` and required is set to ``False``
        otherwise throws an Exception
    :rtype: ``Optional[int]``
    """

    if arg is None:
        if required is True:
            raise ValueError(f'Missing "{arg_name}"')
        return None
    if isinstance(arg, str):
        if arg.isdigit():
            return int(arg)
        raise ValueError(f'Invalid number: "{arg_name}"="{arg}"')
    if isinstance(arg, int):
        return arg
    raise ValueError(f'Invalid number: "{arg_name}"')


def arg_to_timestamp(arg: Any, arg_name: str, required: bool = False) -> Optional[int]:
    """Converts an XSOAR argument to a timestamp (seconds from epoch)

    This function is used to quickly validate an argument provided to XSOAR
    via ``demisto.args()`` into an ``int`` containing a timestamp (seconds
    since epoch). It will throw a ValueError if the input is invalid.
    If the input is None, it will throw a ValueError if required is ``True``,
    or ``None`` if required is ``False.

    :type arg: ``Any``
    :param arg: argument to convert

    :type arg_name: ``str``
    :param arg_name: argument name

    :type required: ``bool``
    :param required:
        throws exception if ``True`` and argument provided is None

    :return:
        returns an ``int`` containing a timestamp (seconds from epoch) if conversion works
        returns ``None`` if arg is ``None`` and required is set to ``False``
        otherwise throws an Exception
    :rtype: ``Optional[int]``
    """

    if arg is None:
        if required is True:
            raise ValueError(f'Missing "{arg_name}"')
        return None

    if isinstance(arg, str) and arg.isdigit():
        # timestamp is a str containing digits - we just convert it to int
        return int(arg)
    if isinstance(arg, str):
        # we use dateparser to handle strings either in ISO8601 format, or
        # relative time stamps.
        # For example: format 2019-10-23T00:00:00 or "3 days", etc
        date = dateparser.parse(arg, settings={'TIMEZONE': 'UTC'})
        if date is None:
            # if d is None it means dateparser failed to parse it
            raise ValueError(f'Invalid date: {arg_name}')

        return int(date.timestamp())
    if isinstance(arg, (int, float)):
        # Convert to int if the input is a float
        return int(arg)
    raise ValueError(f'Invalid date: "{arg_name}"')


''' COMMAND FUNCTIONS '''


def test_module(client: Client, first_fetch_time: int) -> str:
    """Tests API connectivity and authentication

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: XSOAR client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    try:
        client.search_incidents(max_results=1, start_time=first_fetch_time, query=None)
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


def fetch_incidents(client: Client, max_results: int, last_run: Dict[str, int],
                    first_fetch_time: Optional[int], query: Optional[str],
                    ) -> Tuple[Dict[str, int], List[dict]]:
    """This function retrieves new incidents every interval (default is 1 minute).

    :type client: ``Client``
    :param Client: XSOAR client to use

    :type max_results: ``int``
    :param max_results: Maximum numbers of incidents per fetch

    :type last_run: ``Optional[Dict[str, int]]``
    :param last_run:
        A dict with a key containing the latest incident created time we got
        from last fetch

    :type first_fetch_time: ``Optional[int]``
    :param first_fetch_time:
        If last_run is None (first time we are fetching), it contains
        the timestamp in milliseconds on when to start fetching incidents

    :type query: ``Optional[str]``
    :param query:
        query to fetch the relevant incidents

    :return:
        A tuple containing two elements:
            next_run (``Dict[str, int]``): Contains the timestamp that will be
                    used in ``last_run`` on the next fetch.
            incidents (``List[dict]``): List of incidents that will be created in XSOAR

    :rtype: ``Tuple[Dict[str, int], List[dict]]``
    """

    last_fetch = last_run.get('last_fetch', None)
    if last_fetch is None:
        last_fetch = first_fetch_time
    else:
        last_fetch = int(last_fetch)

    latest_created_time = cast(int, last_fetch)
    incidents_result: List[Dict[str, Any]] = []
    last_fetch_in_milliseconds = last_fetch * 1000
    created_filter = timestamp_to_datestring(last_fetch_in_milliseconds)

    if query:
        query += f' and created:>="{created_filter}"'
    else:
        query = f'created:>="{created_filter}"'

    incidents = client.search_incidents(
        query=query,
        max_results=max_results,
        start_time=last_fetch_in_milliseconds
    )

    demisto.debug(f'Fetching incidents since last fetch: {last_fetch}')

    for incident in incidents:
        # todo: check if we can update the if and move it here? does the mech works based on the fetch incidents command?
        incident_result = {
            'name': incident.get('name', 'XSOAR Mirror'),
            'occurred': incident.get('occurred'),
            'rawJSON': json.dumps(incident),
            'type': incident.get('type'),
            'severity': incident.get('severity', 1),
        }

        incidents_result.append(incident_result)

        incident_created_time = arg_to_timestamp(
            arg=incident.get('created'),
            arg_name='created',
            required=True
        )

        # Update last run and add incident if the incident is newer than last fetch
        if incident_created_time > latest_created_time:
            latest_created_time = incident_created_time

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {'last_fetch': latest_created_time + 1}
    return next_run, incidents_result


def search_incidents_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """xsoar-search-incidents command: Search XSOAR incidents

    :type client: ``Client``
    :param Client: XSOAR client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['query']`` query to search incidents
        ``args['start_time']``  start time as ISO8601 date or seconds since epoch
        ``args['max_results']`` maximum number of results to return
        ``args['columns']`` which columns to display in the table

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains incidents

    :rtype: ``CommandResults``
    """

    query = args.get('query')
    start_time = arg_to_timestamp(
        arg=args.get('start_time', '3 days'),
        arg_name='start_time',
        required=False
    )
    max_results = arg_to_int(
        arg=args.get('max_results'),
        arg_name='max_results',
        required=False
    )
    alerts = client.search_incidents(
        query=query,
        start_time=start_time * 1000,
        max_results=max_results
    )
    if not alerts:
        alerts = []

    return CommandResults(
        outputs_prefix='XSOAR.Incident',
        outputs_key_field='id',
        outputs=alerts
    )


def get_incident_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """xsoar-get-incident command: Returns an incident and all entries with given categories and tags

    :type client: ``Client``
    :param Client: XSOAR client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['id']`` incident ID to return
        ``args['from_date']`` only return entries after last update
        ``args['categories']`` only return entries with given categories
        ``args['tags']`` only return entries with given tags

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains an alert

    :rtype: ``CommandResults``
    """

    incident_id = args.get('id', None)
    if not incident_id:
        raise ValueError('id not specified')
    from_date_arg = args.get('from_date', '3 days')
    from_date = arg_to_timestamp(
        arg=from_date_arg,
        arg_name='from_date',
        required=False
    )
    max_results = arg_to_int(
        arg=args.get('max_results'),
        arg_name='max_results',
        required=False
    )
    categories = args.get('categories', None)
    if categories:
        categories = categories.split(',')
    tags = args.get('tags', None)
    if tags:
        tags = tags.split(',')

    incident = client.get_incident(incident_id=incident_id)
    incident_title = incident.get('name', incident_id)

    readable_output = tableToMarkdown(f'Incident {incident_title}', incident)

    entries = client.get_incident_entries(
        incident_id=incident_id,
        from_date=from_date * 1000,
        max_results=max_results,
        categories=categories,
        tags=tags
    )

    readable_output += '\n\n' + tableToMarkdown(f'Last entries since {from_date_arg}', entries)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='XSOAR.Incident',
        outputs_key_field='incident_id',
        outputs=incident
    )


def get_mapping_fields_command(client: Client, args: Dict[str, Any]) -> Dict[str, Any]:
    """get-mapping-fields command: Returns the list of fields for an incident type

    :type client: ``Client``
    :param Client: XSOAR client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['type']`` incident type to retrieve fields for

    :return:
        A ``Dict[str, Any]`` object with keys as field names and description as values

    :rtype: ``Dict[str, Any]``
    """

    incident_type = args.get('type', '')
    incident_fields = client.get_incident_fields()
    fields = {}
    for field in incident_fields:
        if field.get('group') == 0 and (field.get('associatedToAll') or incident_type in field.get('associatedTypes')):
            fields[field.get('cliName')] = f'{field.get("name")} - {field.get("type")} - {field.get("description")}'
    return fields


def get_remote_data_command(client: Client, args: Dict[str, Any], params: Dict[str, Any]) -> List[Dict[str, Any]]:
    """get-remote-data command: Returns an updated incident and entries

    :type client: ``Client``
    :param Client: XSOAR client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['id']`` incident id to retrieve
        ``args['lastUpdate']`` when was the last time we retrieved data

    :return:
        A ``List[Dict[str, Any]]`` first entry is the incident (which can be completely empty) and others are the new entries

    :rtype: ``List[Dict[str, Any]]``
    """

    incident_id = args.get('id')
    demisto.debug(f'Getting update for remote [{incident_id}]')
    last_update = arg_to_timestamp(
        arg=args.get('lastUpdate'),
        arg_name='lastUpdate',
        required=True
    )
    categories = params.get('categories', None)
    if categories:
        categories = categories.split(',')
    else:
        categories = None
    tags = params.get('tags', None)
    if tags:
        tags = tags.split(',')
    else:
        tags = None

    incident = client.get_incident(incident_id=incident_id)
    # If incident was modified before we last updated, no need to return it
    modified = arg_to_timestamp(
        arg=incident.get('modified'),
        arg_name='modified',
        required=False
    )
    if last_update > modified:
        demisto.debug(f'Nothing new in the incident')
        incident = {}

    entries = client.get_incident_entries(
        incident_id=incident_id,
        from_date=last_update * 1000,
        max_results=100,
        categories=categories,
        tags=tags
    )
    formatted_entries = []
    if entries:
        for entry in entries:
            formatted_entries.append({
                'Type': entry.get('type'),
                'Category': entry.get('category'),
                'Contents': entry.get('contents'),
                'ContentsFormat': entry.get('format'),
                'Tags': entry.get('tags'),
                'Note': entry.get('note')
            })
    return [incident] + formatted_entries


def update_remote_system_command(client: Client, args: Dict[str, Any]) -> str:
    """update-remote-system command: pushes local changes to the remote system

    :type client: ``Client``
    :param Client: XSOAR client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['data']`` the data to send to the remote system
        ``args['entries']`` the entries to send to the remote system
        ``args['incidentChanged']`` boolean telling us if the local incident indeed changed or not
        ``args['remoteId']`` the remote incident id

    :return:
        ``str`` containing the remote incident id - really important if the incident is newly created remotely

    :rtype: ``str``
    """
    data = args.get('data')
    entries = args.get('entries')
    incident_changed = args.get('incidentChanged')
    incident_id = args.get('remoteId')

    demisto.debug(f'Sending incident with remote ID [{incident_id}] to remote system\n')

    new_incident_id = incident_id
    if not incident_id or incident_changed:
        if incident_id:
            # First, get the incident as we need the version
            old_incident = client.get_incident(incident_id=incident_id)
            for k in data:
                old_incident[k] = data[k]
            data = old_incident
        else:
            data['createInvestigation'] = True
            data['CustomFields'] = {
                'frompong': 'true'
            }
        updated_incident = client.update_incident(incident=data)
        new_incident_id = updated_incident['id']
        demisto.debug(f'Got back ID [{new_incident_id}]')
    else:
        demisto.debug(f'Skipping [{incident_id}] as it is not new')

    for entry in entries:
        demisto.debug(f'Sending entry ' + entry.get('id'))
        client.add_incident_entry(incident_id=new_incident_id, entry=entry)

    return new_incident_id


def main() -> None:
    api_key = demisto.params().get('apikey')
    base_url = demisto.params().get('url')
    verify_certificate = not demisto.params().get('insecure', False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = arg_to_timestamp(
        arg=demisto.params().get('first_fetch', '3 days'),
        arg_name='First fetch time',
        required=True
    )
    proxy = demisto.params().get('proxy', False)
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers = {
            'Authorization': f'{api_key}'
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            result = test_module(client, first_fetch_time)
            return_results(result)

        elif demisto.command() == 'fetch-incidents':
            query = demisto.params().get('query', None)
            max_results = arg_to_int(
                arg=demisto.params().get('max_fetch'),
                arg_name='max_fetch',
                required=False
            )
            if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
                max_results = MAX_INCIDENTS_TO_FETCH

            next_run, incidents = fetch_incidents(
                client=client,
                max_results=max_results,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time,
                query=query
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'xsoar-search-incidents':
            return_results(search_incidents_command(client, demisto.args()))

        elif demisto.command() == 'xsoar-get-incident':
            return_results(get_incident_command(client, demisto.args()))

        elif demisto.command() == 'get-mapping-fields':
            demisto.results(get_mapping_fields_command(client, demisto.args()))

        elif demisto.command() == 'get-remote-data':
            demisto.results(get_remote_data_command(client, demisto.args(), demisto.params()))

        elif demisto.command() == 'update-remote-system':
            demisto.results(update_remote_system_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()