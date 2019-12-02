from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from array import array
import re

REGEX = "(<a .*?_blank.*/a>)"
REGEX2 = "window.open.*?\)"

class BurpExtender(IBurpExtender, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        # extension name
        callbacks.setExtensionName("Discovering Reverse Tabnabbing")
        # register ourselves as a custom scanner check
        callbacks.registerScannerCheck(self)

    def _get_matches(self, response, match):
        matches = []
        start = 0
        reslen = len(response)
        matchlen = len(match)
        while start < reslen:
            start = self._helpers.indexOf(response, match, True, start, reslen)
            if start == -1:
                break
            matches.append(array('i', [start, start + matchlen]))
            start += matchlen

        return matches

    def _match_obj(self, regex, string):
        match = re.findall(regex, string, re.M)
        if match:
            return match
        else:
            return "None"
    
    def remove_repetidos(self, lista):
        l = []
        for i in lista:
            if i not in l:
                l.append(i)
        l.sort()
        return l


    def doPassiveScan(self, baseRequestResponse):
        x = baseRequestResponse.getResponse()
        responseString = x.tostring()
        regex = self._match_obj(REGEX, responseString)
        regex2 = self._match_obj(REGEX2, responseString)

        if(regex == "None"):
            return None
        if(regex2 == "None"):
            return None

        result = [x for x in regex if x.find("noopener") == -1 ]
        result2 = [x for x in regex2 if x.find("noopener") == -1 ] 

        if(len(result) == 0):
            return None
        if(len(result2) == 0):
            return None

        matches361 = []
        for element in result:
            matches361.append(self._get_matches(responseString, bytearray(element)))

        for element in result2:
            matches361.append(self._get_matches(responseString, bytearray(element)))
        
        flat_list = []
        for sublist in matches361:
            for item in sublist:
                flat_list.append(item)

        matches13 = self.remove_repetidos(flat_list)
      
        
       
        return [CustomScanIssue(
            baseRequestResponse.getHttpService(),
            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
            [self._callbacks.applyMarkers(baseRequestResponse, None, matches13)],
            "Possibility of reverse tabnabbing attack",
            "The response contains target=\"_blank\" without \"noopener\" attribute.", 
            "Reverse tabnabbing is an attack where a page linked from the target page is able to rewrite that page, for example, to replace it with a phishing site. As the user was originally on the correct page they are less likely to notice that it has been changed to a phishing site. If the user authenticates to this new page, then their credentials (or other sensitive data) are sent to the phishing site rather than the legitimate one.", 
            "In general, always add rel = \"noopener\" when opening an external link in a new window or tab. Without this, the new page can access your window object via window.opener and some legacy APIs mean it can navigate your page to a different URL using window.opener.location = newURL.<br/><br/><b>References</b><br/><ul><li><a href='https://www.owasp.org/index.php/Reverse_Tabnabbing' rel='noopener'>Reverse Tabnabbing - OWASP</a></li><li><a href='https://www.jitbit.com/alexblog/256-targetblank---the-most-underestimated-vulnerability-ever' rel='noopener'>The most underestimated vulnerability ever</a></li><li><a href='https://pointjupiter.com/what-noopener-noreferrer-nofollow-explained' rel='noopener'>Explained: noopener</a></li></ul><br/><b>Vulnerability classifications</b><br/><ul><li><a href='https://cwe.mitre.org/data/definitions/1022.html' rel='noopener'>CWE-1022: Use of Web Link to Untrusted Target with window.opener Access</a></li></ul>", 
            "Low")]


    def doActiveScan(self, baseRequestResponse, insertionPoint):
        x = baseRequestResponse.getResponse()
        responseString = x.tostring()
        regex = self._match_obj(REGEX, responseString)
        regex2 = self._match_obj(REGEX2, responseString)

        if(regex == "None"):
            return None
        if(regex2 == "None"):
            return None

        result = [x for x in regex if x.find("noopener") == -1 ]
        result2 = [x for x in regex2 if x.find("noopener") == -1 ] 

        if(len(result) == 0):
            return None
        if(len(result2) == 0):
            return None

        matches361 = []
        for element in result:
            matches361.append(self._get_matches(responseString, bytearray(element)))

        for element in result2:
            matches361.append(self._get_matches(responseString, bytearray(element)))
        
        flat_list = []
        for sublist in matches361:
            for item in sublist:
                flat_list.append(item)

        matches13 = self.remove_repetidos(flat_list)
      
        
       
        return [CustomScanIssue(
            baseRequestResponse.getHttpService(),
            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
            [self._callbacks.applyMarkers(baseRequestResponse, None, matches13)],
            "Possibility of reverse tabnabbing attack",
            "The response contains target=\"_blank\" without \"noopener\" attribute.", 
            "Reverse tabnabbing is an attack where a page linked from the target page is able to rewrite that page, for example, to replace it with a phishing site. As the user was originally on the correct page they are less likely to notice that it has been changed to a phishing site. If the user authenticates to this new page, then their credentials (or other sensitive data) are sent to the phishing site rather than the legitimate one.", 
            "In general, always add rel = \"noopener\" when opening an external link in a new window or tab. Without this, the new page can access your window object via window.opener and some legacy APIs mean it can navigate your page to a different URL using window.opener.location = newURL.<br/><br/><b>References</b><br/><ul><li><a href='https://www.owasp.org/index.php/Reverse_Tabnabbing' rel='noopener'>Reverse Tabnabbing - OWASP</a></li><li><a href='https://www.jitbit.com/alexblog/256-targetblank---the-most-underestimated-vulnerability-ever' rel='noopener'>The most underestimated vulnerability ever</a></li><li><a href='https://pointjupiter.com/what-noopener-noreferrer-nofollow-explained' rel='noopener'>Explained: noopener</a></li></ul><br/><b>Vulnerability classifications</b><br/><ul><li><a href='https://cwe.mitre.org/data/definitions/1022.html' rel='noopener'>CWE-1022: Use of Web Link to Untrusted Target with window.opener Access</a></li></ul>", 
            "Low")] 


    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        # This method is called when multiple issues are reported for the same URL
        # path by the same extension-provided check. The value we return from this
        # method determines how/whether Burp consolidates the multiple issues
        # to prevent duplication
        #
        # Since the issue name is sufficient to identify our issues as different,
        # if both issues have the same name, only report the existing issue
        # otherwise report both issues
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1

        return 0

class CustomScanIssue (IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, background, remediation, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._background = background
        self._remediation = remediation

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return self._background

    def getRemediationBackground(self):
        return self._remediation

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService

