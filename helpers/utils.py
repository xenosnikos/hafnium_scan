import socket
import validators
import logging
from datetime import datetime, timedelta

from helpers import common_strings
from helpers.mongo_connection import db

def validate_domain(domain):
    if not validators.domain(domain):
        return False
    else:
        return True
def resolve_domain_ip(data_input):
    return socket.gethostbyname(data_input)
    
def check_force(data, force, collection, timeframe):
    if force:
        return True
    db[collection].create_index(common_strings.strings['mongo_value'])
    search = db[collection].find_one({common_strings.strings['mongo_value']: data})

    if search is not None:
        if search['status'] == common_strings.strings['status_running'] or \
                search['status'] == common_strings.strings['status_queued']:
            return search['status']
        else:
            force = search['timeStamp'] + timedelta(days=timeframe) < datetime.utcnow()

    if force is False and search is not None:
        return search
    else:
        return True
        
def mark_db_request(value, status, collection):
    try:
        db[collection].update_one({common_strings.strings['mongo_value']: value}, {'$set': {'status': status}},
                                  upsert=True)
    except Exception as e:
        logger = logging.getLogger(collection)
        logger.critical(common_strings.strings['database_issue'], exc_info=e)
    return True