# SubDominal<br />
<p align="center">
  <img src="/imgs/subDom.png">
</p>
SubDominal is a subdomain enumeration tool that leverages multiple methods and data sources to identify sub-domains. Then, if it returns a CNAME that's a known dynamic dns provider that's vulnerable to dangling dns pointers, it notifies you. It also reviews the Wayback Machine for senstive information and when those subdomains were last saved.

## Install
```
git clone https://github.com/AbrictoSecurity/SubDominal.git
cd SubDominal
pip3 install -r requirements.txt
```

## Add API Keys
```
cd SubDominal/Config
nano config.py
```
Add your API keys to the subdom.py file. 
<p align="center">
  <img src="/imgs/api.png">
</p>

## Run/Operate
```
python3 subdom.py -h 
```

## Notes
Be careful with the bruteforce option as it will take time and it will create a lot of noise.
