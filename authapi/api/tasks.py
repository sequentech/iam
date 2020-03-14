# This file is part of authapi.
# Copyright (C) 2014-2020  Agora Voting SL <contact@nvotes.com>

# authapi is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# authapi  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with authapi.  If not, see <http://www.gnu.org/licenses/>.

import requests
import json
from djcelery import celery
from django.conf import settings
from django.core.mail import send_mail
from django.db.models import Count, OuterRef, Subquery, Q
from django.shortcuts import get_object_or_404
from django.contrib.auth.models import User
from celery.utils.log import get_task_logger

import plugins
from authmethods.sms_provider import SMSProvider
from utils import send_codes, genhmac, reproducible_json_dumps
from .models import Action, AuthEvent, BallotBox, TallySheet

logger = get_task_logger(__name__)

def parse_json_request(request):
    '''
    Returns the request body as a parsed json object
    '''
    return json.loads(request.content.decode('utf-8'))

def census_send_auth_task(pk, ip, config=None, userids=None, auth_method=None, sender_uid=None, **kwargs):
    """
    Send an auth token to census
    """
    from .models import AuthEvent, ACL, UserData

    e = get_object_or_404(AuthEvent, pk=pk)

    # If the auth_method is not set, use the default authmethod for the election
    if auth_method is None:
        auth_method = e.auth_method

    new_census = []

    if sender_uid is not None:
        print("Sender user id = %d" % sender_uid)

    census = []
    if userids is None:
        new_census = ACL.objects.filter(perm="vote", object_type="AuthEvent", object_id=str(pk))
    else:
        users = User.objects.filter(id__in=userids)
        userdata = UserData.objects.filter(user__in=users)
        new_census = ACL.objects.filter(perm="vote", object_type="AuthEvent", object_id=str(pk), user__in=userdata)

    census = []
    if e.auth_method == auth_method:
        census = [i.user.user.id for i in new_census]
    else:
        for item in new_census:
           if "sms" == auth_method and item.user.tlf:
               census.append(item.user.user.id)
           elif "email" == auth_method and item.user.user.email:
               census.append(item.user.user.id)
    
    extend_errors = plugins.call("extend_send_message", e, len(census), kwargs)
    if extend_errors:
        # Only can return one error at least for now
        return extend_errors[0]
    send_codes.apply_async(args=[census, ip, auth_method, config, sender_uid, pk])

def launch_tally(auth_event):
    '''
    Launches the tally of an auth_event.
    Called by process_tallies() celery task.
    '''
    if len(settings.AGORA_ELECTIONS_BASE) == 0:
        return

    callback_base = settings.AGORA_ELECTIONS_BASE[0]
    callback_url = "%s/api/election/%s/tally-voter-ids" % (
        callback_base,
        auth_event.id
    )

    if auth_event.parent is None:
        parent_auth_event = auth_event
    else:
        parent_auth_event = auth_event.parent

    # dump of the voter ids
    voter_ids = User.objects\
        .filter(
            is_active=True,
            userdata__event=parent_auth_event
        )\
        .values('username')
    voter_ids_list = list(voter_ids)

    agora_elections_request = requests.post(
        callback_url,
        json=voter_ids_list,
        headers={
            'Authorization': genhmac(
                settings.SHARED_SECRET,
                "1:AuthEvent:%s:tally" % auth_event.id
            ),
            'Content-type': 'application/json'
        }
    )
    if agora_elections_request.status_code != 200:
        logger.error(
            "launch_tally.post\n" +
            "agora_elections.callback_url '%r'\n" +
            "agora_elections.data.len = '%r'\n" +
            "agora_elections.status_code '%r'\n" +
            "agora_elections.text '%r'\n",
            callback_url, 
            len(voter_ids_list), 
            agora_elections_request.status_code, 
            agora_elections_request.text
        )
        auth_event.tally_status = 'notstarted'
        auth_event.save()

        # log the action
        if 'no votes in this election' in agora_elections_request.text:
            action_name = 'authevent:tally:error-no-votes'
        else:
            action_name = 'authevent:tally:error'

        action = Action(
            executer=None,
            receiver=None,
            action_name=action_name,
            event=parent_auth_event,
            metadata=dict(
                auth_event=auth_event.pk,
                request_status_code=agora_elections_request.status_code,
                request_text=agora_elections_request.text
            )
        )
        action.save()


    logger.info(
        "launch_tally.post\n" +
        "agora_elections.callback_url '%r'\n" +
        "agora_elections.data.len = '%r'\n" +
        "agora_elections.status_code '%r'\n" +
        "agora_elections.text '%r'\n",
        callback_url, 
        len(voter_ids_list), 
        agora_elections_request.status_code, 
        agora_elections_request.text
    )
    auth_event.tally_status = 'started'
    auth_event.save()

    # log the action
    action = Action(
        executer=None,
        receiver=None,
        action_name='authevent:tally:started',
        event=parent_auth_event,
        metadata=dict(
            auth_event=auth_event.pk
        )
    )
    action.save()

def update_tally_status(auth_event):
    '''
    Receives the status from agora-elections and updates the AuthEvent.
    Called by process_tallies() celery task.
    '''

    if auth_event.parent is None:
        parent_auth_event = auth_event
    else:
        parent_auth_event = auth_event.parent
    
    if len(settings.AGORA_ELECTIONS_BASE) == 0:
        return

    callback_base = settings.AGORA_ELECTIONS_BASE[0]
    callback_url = "%s/api/election/%s" % (
        callback_base,
        auth_event.id
    )

    agora_elections_request = requests.get(
        callback_url,
        headers={
            'Content-type': 'application/json'
        }
    )
    if agora_elections_request.status_code != 200:
        logger.error(
            "update_tally_status.post\n" +
            "agora_elections.callback_url '%r'\n" +
            "agora_elections.status_code '%r'\n" +
            "agora_elections.text '%r'\n",
            callback_url, 
            agora_elections_request.status_code, 
            agora_elections_request.text
        )

    logger.info(
        "update_tally_status.post\n" +
        "agora_elections.callback_url '%r'\n" +
        "agora_elections.status_code '%r'\n" +
        "agora_elections.text '%r'\n",
        callback_url, 
        agora_elections_request.status_code, 
        agora_elections_request.text
    )
    updated_election = parse_json_request(agora_elections_request)
    election_state = updated_election['payload']['state']

    if election_state in ['tally_error', 'stopped', 'started']:
        auth_event.tally_status = 'notstarted'
        auth_event.save()

        # log the action
        action = Action(
            executer=None,
            receiver=None,
            action_name='authevent:tally:error-during-tally',
            event=parent_auth_event,
            metadata=dict(
                auth_event=auth_event.pk
            )
        )
        action.save()
    elif election_state in ['tally_ok', 'results_ok', 'results_pub']:
        auth_event.tally_status = 'success'
        auth_event.save()
        
        # log the action
        action = Action(
            executer=None,
            receiver=None,
            action_name='authevent:tally:success',
            event=parent_auth_event,
            metadata=dict(
                auth_event=auth_event.pk
            )
        )
        action.save()

@celery.task(name='tasks.process_tallies')
def process_tallies():
    '''
    Process tallies does two tasks:
    1. Launch the next pending tally.
    2. Review which tally has succeeded and updates corresponding
       AuthEvents.
    '''
    tallying_events = AuthEvent.objects\
        .filter(tally_status='started')\
        .order_by('id')

    # Review which tallies have succeeded and update corresponding AuthEvents
    for auth_event in tallying_events:
        update_tally_status(auth_event)

    pending_events = AuthEvent.objects\
        .filter(tally_status='pending')\
        .order_by('id')

    # if no simultaneous election, then launch tally
    if tallying_events.count() == 0 and pending_events.count() > 0:
        launch_tally(pending_events[0])

@celery.task(name='tasks.update_ballot_boxes_config')
def update_ballot_boxes_config(auth_event_id):
    '''
    Updates in Agora-elections the ballot boxes configuration
    '''
    auth_event = get_object_or_404(AuthEvent, pk=auth_event_id)

    # if this auth event has a parent, update also the parent
    if auth_event.parent_id is not None:
        update_ballot_boxes_config.apply_async(args=[auth_event.parent_id])
    
    # A. try to do a call to agora_elections to update the election results
    # A.1 get all the tally sheets for this election, last per ballot box,
    # including ballot boxes from children auth events
    subq = TallySheet.objects\
        .filter(ballot_box=OuterRef('pk'))\
        .order_by('-created', '-id')

    tally_sheets = BallotBox.objects\
        .filter(
            Q(auth_event_id=auth_event_id) |
            Q(auth_event__parent_id=auth_event_id)
        )\
        .annotate(
            data=Subquery(
                subq.values('data')[:1]
            ), 
            num_tally_sheets=Count('tally_sheets')
        )\
        .filter(num_tally_sheets__gt=0)
    
    # send the ballot_box_name
    for tally_sheet in tally_sheets:
        tally_sheet.data = json.loads(tally_sheet.data, encoding='utf-8')
        tally_sheet.data['ballot_box_name'] = tally_sheet.name

    # craft ballot_boxes_config
    ballot_boxes_config = reproducible_json_dumps([
        tally_sheet.data
        for tally_sheet in tally_sheets
    ])

    # A.2 call to agora-elections
    for callback_base in settings.AGORA_ELECTIONS_BASE:
        callback_url = "%s/api/election/%s/update-ballot-boxes-config" % (
            callback_base,
            pk
        )

        r = requests.post(
            callback_url,
            json=ballot_boxes_config,
            headers={
                'Authorization': genhmac(
                    settings.SHARED_SECRET,
                    "1:AuthEvent:%s:update-ballot-boxes-results-config" % pk
                ),
                'Content-type': 'application/json'
            }
        )
        if r.status_code != 200:
            LOGGER.error(\
                "TallySheetView.post\n"\
                "agora_elections.callback_url '%r'\n"\
                "agora_elections.data '%r'\n"\
                "agora_elections.status_code '%r'\n"\
                "agora_elections.text '%r'\n",\
                callback_url, data, r.status_code, r.text
            )

            return json_response(
                status=500,
                error_codename=ErrorCodes.GENERAL_ERROR)

        LOGGER.info(\
            "TallySheetView.post\n"\
            "agora_elections.callback_url '%r'\n"\
            "agora_elections.data '%r'\n"\
            "agora_elections.status_code '%r'\n"\
            "agora_elections.text '%r'\n",\
            callback_url, data, r.status_code, r.text
        )