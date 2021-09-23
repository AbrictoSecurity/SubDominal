# SubDominal<br />
<p align="center">
  <img src="/imgs/subDom.png">
</p>
SubDominal is a subdomain enumeration tool that leverages the top 10,000 subdomains to check and see if they exist for a given domain. Then, if it returns a CNAME that's a known dynamic dns provider that's vulnerable to dangling dns pointers, it notifies you. It also reviews the Wayback Machine for senstive information and when those subdomains were last saved.

## Install
```
git clone https://github.com/AbrictoSecurity/SubDominal.git
```

## Add Shodan API Key
```
cd SubDominal
nano subdom.py
```
Add your Shodan API key to the subdom.py file. 
<p align="center">
  <img src="/imgs/api.png">
</p>

## Run/Operate
```
python3 subdom.py
```

## Notes
Make sure that you have dnspython installed.
```
pip3 install dnspython
```
