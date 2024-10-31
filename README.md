# sharpxss
#### Video Demo:  [<YOUTUBE VIDEO>](https://youtu.be/-CvcAF_JxkM)
#### Description:
This is a web application analyzing tool written entirely in C#. It uses the Selenium.Support package to test the web application. By default it runs a chrome driver,
but I use Firefox, so I opted for the Firefox Driver.

The tool fetches the user's IP via https://ipify.org through an API. The IP address is then sent to https://ipinfo.io
from which the tool fetches the full information about the IP in JSON. The information is then shown to the user.

The point of this is to warn the user about the IP they are currently using and if needed, to switch to a VPN (I show this in the video). The User Interface is a custom CLI for 
an added personal touch. The Payloads can be customized, viewed and if neccessary edited. The target URL must be adequate or the tool will not function correctly. 
For example, opt for https://example.com/?s= instead of https://example.com . The tool utilizes the search functionality of the target to try and run executable XSS payloads. 

I was inspired to create this tool by my background with C# and some experience in Cybersecurity, so I wanted to create something meaningful and prove that C# is still alive and 
kicking.
