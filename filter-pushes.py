"""
This inline script can be used to dump flows as HAR files.
"""


import json
import sys
import base64
import zlib
import sys
import os
import mahi_pb2
import string
import random

from pprint import pprint

from datetime import datetime
import pytz

import mitmproxy

from mitmproxy import version
from mitmproxy.utils import strutils
from mitmproxy.net.http import status_codes

PUSHES = {}

epoch = datetime.utcfromtimestamp(0)

def unix_time_millis(dt):
    return (dt - epoch).total_seconds() * 1000.0

def start():
    """
        Called once on script startup before any other events.
    """
    PUSHES.update({
        'entries':[]
        });

def response(flow):
    
    """
       Called when a server response has been received.
    """
    if ('h2-pushed-stream' in flow.metadata and flow.metadata['h2-pushed-stream'] == True):
        PUSHES["entries"].append({'url':flow.request.url, 'timestamp':unix_time_millis(datetime.utcfromtimestamp(flow.request.timestamp_start)), 'mime': flow.response.headers.get('Content-Type', '')})


def done():
    """
        Called once on script shutdown, after any other events.
    """
    print(json.dumps(sorted(PUSHES['entries'],key=lambda x: x['timestamp'])))
