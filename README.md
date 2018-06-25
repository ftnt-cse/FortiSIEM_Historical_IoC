# FortiSIEM_Historical_IoC
enables FortiSIEM to find previously infected machines after each FortiGuard IoC update.

**Intro:**
FortiSIEM as designed checks the real-time events for IoC fetches from various threat intelligence sources. 
This project aims to add historical IoC visibility into FortiSIEM.

**Prerequisites:**
1. FortiSIEM 5.X instance
2. Python 2.7.7+
3. python pg8000 package
4. a valid postgresql credentials (create user and having phoenixdb privileges)

**How it works:**
1. Each time the IoC database is updated an "IoC update incident" is generated
2. The generated incident triggers “Historical_IoC.py” python script through a remediation action
3. The script will:
- Query FortiSIEM for the last X hours sessions summary {Srcip,dstip,Count(hits)} using FortiSIEM REST API. “report_hours” - - - variable is used to determine the report time length, default is 10
- Query FortiSIEM local database for the list of the current FortiGuard IoC (dstip)
- The script then compares the destination IPs of the past hours with the newly downloaded IoCs 
- For each match, a syslog message with the incident details:
 * time of the first connection
 * source IP
 * Destination IP
 * Connection count
Is sent to FortiSIEM with PHBox format. The event then can be used to remediate the infected machines.

**Components:**
IoC updated rule
Historical_IoC.py

**Installation:**
1.	Copy Historical_IoC.py to FortiSIEM (typically to /home/admin/scripts)
2.	Import the IoC updated rule in FortiSIEM and make sure it triggers an incident each time IoCs are updated from the cloud
4.	Set Historical_IoC.py as remediation script for the IoC update incident
5.	(optional) set a remediation script for Historical IoC Detected incident
