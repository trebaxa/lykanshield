# LykannShield
## Blocks SQL Injection, bad bots, bad IPs and different filter like mime filter.

**Join our global network to protect your pages from hackers.** 

**Autodetects WordPress,TYPO3,Keimeno**
***can be used on any PHP application

- central server for bad ips,bots and injection filter
- injection protection
- file upload filter
- mime type validation
- reports to central server
- every webproject, which uses LykanShield, helps other projects to get protected
- totally free to use
- internet security should be for free

This project should help us developer to protect our PHP projects from hacking. Bad IPs will be reported to central server 
and hlock updates hisself with a current list of bad ips, bots and SQL injection rules.
Be part of the network and help us to get the web safer!
 
This version is compatible with any PHP project. It autodetects Keimenno, Wordpress, Joomla and Typo3.
 
### Quick implementation
**add in your project index.php:**

```php
  <?PHP
  require ('./includes/lykan.class.php');
  lykan::run(dirname(__FILE__));
```
 
The keimenbo CMS includes the LykanShield project already. It is in the core implemented.
