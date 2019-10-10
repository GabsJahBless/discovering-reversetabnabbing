# Discovering Reverse Tabnabbing

*Reverse tabnabbing* is an attack where a page linked from the target page is able to rewrite that page, for example, to replace it with a phishing site. As the user was originally on the correct page they are less likely to notice that it has been changed to a phishing site. If the user authenticates to this new page, then their credentials (or other sensitive data) are sent to the phishing site rather than the legitimate one.
Because of this I created the *Discovering Reverse Tabnabbing*, that is a Burp extension written in Python which helps to locate HTML links that use the target="_blank" attribute, omitting the rel="noopener" attribute. 
