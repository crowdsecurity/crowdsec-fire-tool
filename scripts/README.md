## Description
Script to download and configure crowdsec using the crowdsec-fire-tool

This is intended to be used for Proof-Of-Concepts to make a simpler installer that will configure the system.

## Usage

This script has some different options these are:

#### Install
```
sudo ./crowdsec.sh install
```

Install will prompt you serveral questions about your enterprise processes:

Do you want to install CrowdSec from the official repository (packagecloud.io)? if Yes then the script will download and configure our repository located on [packagecloud](https://packagecloud.io/crowdsec/crowdsec)
If no then script will ask if you wish to install via the tarball located on our latest release.
If both are answered no then the script will fail.

#### Configure

```
sudo ./crowdsec.sh configure
```

The configure option **MUST** run after the install command has completed successfully. The configure command configure crowdsec to download and use the fire data directly within a scenario. 

#### Type matrix

type | description
-----|------------
syslog | Syslog logs
apache2 | Apache2 logs
asterisk | Asterisk logs
caddy | Caddy logs
cowrie | Cowrie logs
cpanel | Cpanel logs
dovecot |  Dovecot logs
dropbear | Dropbear logs
exchange-imap | Exchange IMAP logs
exim | Exim logs
home-assistant | Home Assistant logs
iis | IIS logs
kasm | Kasm logs
litespeed | Litespeed logs
magento-extension | Magento Extension logs
mariadb | MariaDB logs
mssql | MSSQL logs
mysql | MySQL logs
nginx | Nginx logs
nginx-proxy-manager |  Nginx Proxy Manager logs
odoo | Odoo logs
postgres | Postgres logs
postfix/smtpd | Postfix SMTPD logs
postfix/smtps/smtpd | Postfix SMTPS SMTPD logs
postfix/submission/smtpd | Postfix Submission SMTPD logs
postfix/smtps-haproxy/smtpd | Postfix SMTPS HAProxy SMTPD logs
postfix/submission-haproxy/smtpd | Postfix Submission HAProxy SMTPD logs
postfix/postscreen | Postfix Postscreen logs
haproxy/postscreen | HAProxy Postscreen logs
proftpd | Proftpd logs
sshd | SSHD logs
suricata-fastlogs | Suricata Fastlogs logs
synoscgi_SYNO.API.Auth_7_login | Synology Auth logs
tcpdump | TCPDump logs
ts3 | Teamspeak3 logs
thehive | TheHive logs
traefik | Traefik logs
vsftpd | Vsftpd logs
zimbra | Zimbra logs
pure-ftpd | Pure-ftpd logs
authelia | Authelia logs
emby | Emby logs
gitea | Gitea logs
jellyseerr | Jellyseerr logs
ombi | Ombi logs
pterodactyl | Pterodactyl logs
Prowlarr | Prowlarr logs
Radarr | Radarr logs
mono | Mono logs
Sonarr | Sonarr logs
sshesame | SSHesame logs


