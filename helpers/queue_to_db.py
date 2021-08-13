from datetime import datetime
import logging
from helpers import common_strings
from helpers.mongo_connection import db

def hafniumscan_response_db_addition(value, output):
    try:
        db.hafniumScan.find_one_and_update({common_strings.strings['mongo_value']: value},
                            {'$set': {'status': common_strings.strings['status_finished'],
                                    'timeStamp': datetime.utcnow(), 'output': output}})
    except Exception as e:
        logger = logging.getLogger(common_strings.strings['hafniumscan'])
        logger.critical(common_strings.strings['database_issue'], exc_info=e)