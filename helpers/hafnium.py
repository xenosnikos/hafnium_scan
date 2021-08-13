
from enum import Enum

check_ep = ('shellex.aspx', 'iistart.aspx', 'one.aspx', 't.aspx', 'aspnettest.aspx', 'error.aspx',
                    'discover.aspx', 'supp0rt.aspx', 'shell.aspx', 'HttpProxy.aspx', '0QWYSEXe.aspx', 'load.aspx',
                    'sol.aspx', 'RedirSuiteServerProxy.aspx', 'OutlookEN.aspx', 'errorcheck.aspx', 'web.aspx',
                    'help.aspx', 'document.aspx', 'errorEE.aspx', 'errorEEE.aspx', 'errorEW.aspx', 'errorFF.aspx',
                    'healthcheck.aspx', 'aspnet_www.aspx', 'aspnet_client.aspx', 'xx.aspx', 'aspnet_iisstart.aspx')

class Risk(Enum):
    CLEAR = "CLEAR"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

def get_risk(value):
    if(value>=0 and value<85):
        return Risk.CRITICAL.name
    elif(value>84 and value<90):
        return Risk.HIGH.name
    elif(value>89 and value<=94):
        return Risk.MEDIUM.name
    else:
        return Risk.CLEAR.name