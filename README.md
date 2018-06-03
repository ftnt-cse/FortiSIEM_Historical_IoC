# FortiSIEM_Historical_IoC
enables FortiSIEM to find historical IoC after each FortiGuard IoC update

##Intro:
FortiSIEM as designed checks the real-time events for IoC fetches from various threat intelligence sources. 
This project aims to add historical IoC visibility into FortiSIEM.

##How it works:
Each time the IoC is updated we run a Historical_IoC.py which has to be deployed on FSM instance. It will:
1.	Query FortiSIEM for the last X seconds session table summary {Srcip,dstip,Count(hits)} using FortiSIEM REST API
2.	Query FortiSIEM local database for the list of the current FortiGuard IoC (dstip)
3.	Send a syslog to FortiSIEM for each IoC match. The syslog uses 
4.	The syslog triggers a Historical IoC Detected incident

##Components:
IoC updated rule
Historical_IoC.py

##Installation:
1.	Copy Historical_IoC.py to FortiSIEM (typically to /home/admin/scripts)
2.	Import the IoC updated rule
3.	Import Historical IoC Detected rule
4.	Set Historical_IoC.py as remediation script for the incident
5.	(optional) set a remediation script for Historical IoC Detected incident

