import os
from flask_restful import Resource, reqparse, request, inputs
import threading
from enum import Enum
import dns.resolver
from helpers import auth_check, common_strings, logging_setup, utils, hafnium, queue_to_db
import requests
from queue import Queue
import nmap

portscan_args = reqparse.RequestParser()
portscan_args.add_argument(common_strings.strings['key_value'], help=common_strings.strings['domain_required'], required=True)
portscan_args.add_argument(common_strings.strings['input_force'], type=inputs.boolean, default=True)
logger = logging_setup.initialize(common_strings.strings['hafniumscan'], 'logs/hafniumscan_api.log')

data = {}
issue_found = False
count = 0
q = Queue()

class Risk(Enum):
    FAIL = "FAIL"
    PASS = "PASS"

class HafniumScan(Resource):

    @staticmethod
    def ep_check(url):
        global data, issue_found, count
        try:
            resp = requests.get(url=url, verify=False)
        except requests.exceptions.ConnectionError:
            data[url] = 'Connection Refused'
            return
        except requests.exceptions.TooManyRedirects:
            data[url] = 'Too many Redirects'
            return

        if resp.status_code == 200:
            if hasattr(resp, 'url') and 'errorFE.aspx' in resp.url:
                data[url] = False
                return
            else:
                finding = {'etag': resp.headers['ETag'] if 'ETag' in resp.headers else False,
                           'powered': resp.headers[
                               'X-Powered-By'] if 'X-Powered-By' in resp.headers else False,
                           'server': resp.headers['Server'] if 'Server' in resp.headers else False}
                data[url] = finding
                issue_found = True
                count += 1
        else:
            if hasattr(resp, 'url') and 'errorFE.aspx' in resp.url:
                data[url] = False
                return
            else:
                data[url] = resp.status_code

    @staticmethod
    def threader():
        while True:
            worker = q.get()
            HafniumScan.ep_check(worker)
            q.task_done()
            break


    @staticmethod
    def post():
        global data, issue_found, count, q
        auth = request.headers.get('Authorization')

        authentication = auth_check.auth_check(auth)

        args = portscan_args.parse_args()

        value = args['value']
        
        logger.debug(f"hafniumscan request received for {value}")

        breach_outputs = {}

        check_ep = hafnium.check_ep

        folders = ('/aspnet_client/', '/aspnet_client/system_web/', '/owa/auth/')

        if authentication['status'] == 401:
            logger.debug(f"Unauthenticated hafnium request received for {value}")
            return authentication, 401

        if not utils.validate_domain(value):
            logger.debug(f"Domain that doesn't match regex request received - {value}")
            return {
                    'message': f'{value} is not a valid domain, please try again'
                }, 400

        # if domain doesn't resolve into an IP, throw a 400 as domain doesn't exist in the internet
        try:
            ip = utils.resolve_domain_ip(value)
        except Exception as e:
            logger.debug(f"Domain that doesn't resolve to an IP was requested - {value, e}")
            return {
                       common_strings.strings['message']: f"{value}" + common_strings.strings['unresolved_domain_ip']
                   }, 400
        if args[common_strings.strings['input_force']]:
            force = True
        else:
            force = False  
        
        # based on force - either gives data back from database or gets a True back to continue with a fresh scan
        check = utils.check_force(value, force, collection=common_strings.strings['hafniumscan'],
                                  timeframe=int(os.environ.get('DATABASE_LOOK_BACK_TIME')))    
        
        # if a scan is already requested/in-process, we send a 202 indicating that we are working on it
        if check == common_strings.strings['status_running'] or check == common_strings.strings['status_queued']:
            return {'status': check}, 202
        
        # if database has an entry with results and force is false, send it
        elif type(check) == dict and check['status'] == common_strings.strings['status_finished']:
            logger.debug(f"hafniumscan response sent for {value} from database lookup")
            return check['output'], 200

        else:
            # mark in db that the scan is queued
            utils.mark_db_request(value, status=common_strings.strings['status_queued'],
                                  collection=common_strings.strings['hafniumscan'])
            output = {common_strings.strings['key_value']: value, common_strings.strings['key_ip']: ip}
        try:
            mx_records = set()
            mx_on_prem_records = {}
            mx_cloud_records = {}
            mx_patch_status = {}

            try:
                for mx_record in dns.resolver.query(value, 'MX'):
                    # Ternary operator
                    mx_records.add(str(mx_record.exchange)[:len(str(mx_record.exchange)) - 1] if
                                str(mx_record.exchange)[len(str(mx_record.exchange)) - 1] == '.' else
                                str(mx_record.exchange))
            except:
                return {
                    value: {'No MX': 'None'}
                }

            for each in mx_records:
                try:
                    ip = utils.resolve_domain_ip(each)
                except:
                    mx_cloud_records[each] = 'Cannot resolve IP'
                    continue
                nmap_patch = nmap.PortScanner()
                patch_check = nmap_patch.scan(hosts=ip, ports='443', arguments='--script=/usr/local/share/nmap'
                                                                            '/scripts/http-vuln-cve2021-26855.nse')
                # Check to see if this path exists in the nmap result:
                # patch_check['scan']['50.245.242.69']['tcp'][443]['script']['http-vuln-cve2021-26855']
                if 'scan' in patch_check and ip in patch_check['scan'] and 'tcp' in patch_check['scan'][ip] and 443 in \
                        patch_check['scan'][ip]['tcp'] and 'script' in patch_check['scan'][ip]['tcp'][443] and \
                        'http-vuln-cve2021-26855' in patch_check['scan'][ip]['tcp'][443]['script']:
                    mx_patch_status[each] = 'vulnerable'
                else:
                    mx_patch_status[each] = 'patched'
                if value == each[-len(value):]:
                    mx_on_prem_records[each] = ip
                else:
                    mx_cloud_records[each] = 'Cloud'

            if len(mx_on_prem_records) == 0:
                breach_outputs[value] = mx_cloud_records
                breach_outputs['risk'] = hafnium.Risk.CLEAR.name
            else:
                mx_outputs = {}

                pass_count = 0 
                for target_value, target_ip in mx_on_prem_records.items():
                    ip_breaches = {}

                    for x in range(84):
                        t = threading.Thread(target=HafniumScan.threader, daemon=False)
                        t.start()

                    data = {}
                    issue_found = False
                    count = 0

                    for folder in folders:
                        for endpoint in check_ep:
                            url = None
                            url = f"https://{target_value}{folder}{endpoint}"
                            q.put(url)

                    q.join()

                    ip_breaches['ip'] = target_ip
                    ip_breaches['patch_status'] = mx_patch_status[target_value]
                    ip_breaches['type'] = 'on-prem'
                    ip_breaches['breached'] = issue_found
                    ip_breaches['count'] = count
                    ip_breaches['data'] = data

                    if len(mx_cloud_records) != 0:
                        mx_outputs.update(mx_cloud_records)
                    risk_checker = ip_breaches['data'][f"https://{target_value}{folders[0]}{check_ep[0]}"]
                    ip_breaches['risk'] = Risk.PASS.name if type(risk_checker)==str and risk_checker.count("Connection Refused")>0 else Risk.FAIL.name
                    if ip_breaches['risk'] == 'PASS':
                        pass_count += 1
                    mx_outputs[target_value] = ip_breaches
                breach_outputs[value] = mx_outputs
                breach_outputs['risk'] = hafnium.get_risk((pass_count/len(mx_records))*100)
        except Exception as e:
            logger.critical(common_strings.strings['error'], exc_info=e)
            return 'hafniumscan is currently unavailable', 503
        
        output.update(breach_outputs)

        queue_to_db.hafniumscan_response_db_addition(value, output)

        return output, 200
