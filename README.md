# Discovering Reverse Tabnabbing

*Reverse tabnabbing* is an attack where a page linked from the target page is able to rewrite that page, for example, to replace it with a phishing site. As the user was originally on the correct page they are less likely to notice that it has been changed to a phishing site. If the user authenticates to this new page, then their credentials (or other sensitive data) are sent to the phishing site rather than the legitimate one.
Because of this I created the *Discovering Reverse Tabnabbing*, that is a Burp extension written in Python which helps to locate HTML links that use the target="_blank" attribute, omitting the rel="noopener" attribute. 

## Usage 
**1.** Download the "Standalone Jar" version of Jython clicking <a href="http://www.jython.org/downloads.html">here</a>  
**2.** Open the Burp Suite tool  
**3.** Go to tab *Extender* -> *Options*  
**4.** At *Python Environment* select the *Jython* file downloaded on **step 1**  
**5.** After, go to *Extender* -> *BApp Store* and search for *Discover Reverse Tabnabbing* extension name
**6.** Click on and install it  

Now, when initiating a Passive or Active Scan, issues related to this vulnerability will appear on the *Dashboard* tab.
Please, give it a rate :)
