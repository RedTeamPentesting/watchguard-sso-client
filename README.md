# Proof of Concept for Watchguard SSO Agent Vulnerabilitites (CVE-2024-6592, CVE-2024-6593, CVE-2024-6594)

Details are described in our advisories available at:

 * [CVE-2024-6592](https://www.redteam-pentesting.de/advisories/rt-sa-2024-006)
 * [CVE-2024-6593](https://www.redteam-pentesting.de/advisories/rt-sa-2024-007)
 * [CVE-2024-6594](https://www.redteam-pentesting.de/advisories/rt-sa-2024-008)

The script requires the Python [click](https://click.palletsprojects.com/) library to run.

# Examples
## Issue Arbitrary Commands to SSO Clients

The subcommand `command` can be used to issue commands to the Telnet interface of a Watchguard SSO client. For example, the list of currently logged-in users can be retrieved:

 ```
$ ./wgclient.py command --host 'client.domainname' 'get user a'
 ```


## Retrieve Log files from SSO Clients

The subcommand `logfile` can be used to retrieve log files of an Watchguard SSO client. The log files may also include crash memory dumps (see [CVE-2024-6592](https://www.redteam-pentesting.de/advisories/rt-sa-2024-006) for details).

```
$ ./wgclient.py logfile --host 'client.domainname'
```

## Calculate Authentication Bypass Secret

The subcommand `authbypass` can be used to calculated a secret value to login to the Telnet management interface of an Watchguard SSO agent. To secret is calculated from the banner that the agent sends upon connection, which has to be provided as argument. Details are available in the advisory for [CVE-2024-6593](https://www.redteam-pentesting.de/advisories/rt-sa-2024-007).

```
$ ./wgclient.py authbypass 'EVENT 350 log info Connected to [...]'
```