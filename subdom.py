import time

import dns.resolver
import subprocess
import concurrent.futures
import json
import requests
from progress.spinner import Spinner
from shodan import Shodan
import shodan
import os
import argparse
from progress.bar import IncrementalBar
from Config import config


parser = argparse.ArgumentParser(description='Subdomain Eunmeration tool')
parser.add_argument('--domain', '-d', dest="domain", type=str, required=True,
                    help='When defining the domain to be scanned, use the parent domain.\n\tLike: google.com or '
                         'company.org')
parser.add_argument('--sub', '-s', dest="sub", type=str,
                    help='Additonal subdomain list.')
parser.add_argument('--brute', '-b', default=False, action="store_true",
                    help='This flag extends the scan for all possible combinations of 2 to 4 characters. Warning:'
                         ' This will take a while.')
parser.add_argument('--deep', '-dp', default=False, action="store_true",
                    help="Scans for subdomains within subdomains. Like 'abc.abc.google.com'")
parser.add_argument('--shodan', '-sd', default=False, action="store_true",
                    help="To conduct a shodan scan on the results. This requires an API key within Config/config.py.")

parser.add_argument('--way_osint', '-wo', default=False, action="store_true",
                    help="Looks for sensitive get parameters within the wayback.")

parser.add_argument('--way_history', '-wh', default=False, action="store_true",
                    help="Looks for if the wayback machine has copied this site in the past.")

args = parser.parse_args()

bf_doc = []
sites = []
new_sites = []


BLUE = '\033[94m'
GREEN = '\033[92m'
WARNING = '\033[93m'
WHITE = '\033[97m'
ERROR = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'

site2 = []
ips = []


def cn_scan(domain):
    url = f"https://crt.sh/?CN={domain}"
    req = requests.get(url=url)
    file = open(".temp.txt", 'w')
    file.write(req.text)
    file.close()
    cut = f"cat .temp.txt | grep {domain}| cut -d '>' -f 2 | cut -d '<' -f 1 | sort " \
          f"| uniq | grep -v 'Type:' | sed -e 's+*.++g' | sed -e 's+?.++g' > {domain}_clean_crt_scan.txt"
    subprocess.call(cut, shell=True)
    cut = f"cat .temp.txt | grep {domain}| cut -d '>' -f 2 | cut -d '<' -f 1 | sort " \
          f"| uniq | grep -v 'Type:' | sed -e 's+?.++g' > {domain}_crt_scan.txt"
    subprocess.call(cut, shell=True)
    clean = "rm .temp.txt"
    subprocess.call(clean, shell=True)


def ht_scan(domain):
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    req = requests.get(url=url)
    file = open(".temp.txt", 'w')
    file.write(req.text)
    file.close()
    cut = f"cat .temp.txt | grep {domain} | cut -d ',' -f 1 | sort |uniq  > {domain}_clean_hackertarget_scan.txt"
    subprocess.call(cut, shell=True)
    cut = f"cat .temp.txt  > {domain}_hackertarget_scan.txt"
    subprocess.call(cut, shell=True)
    clean = "rm .temp.txt"
    subprocess.call(clean, shell=True)


def smate(domain):
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    if config.sslmate != "":
        header = {"Authorization": "Bearer " + config.sslmate}
        req = requests.get(url=url, headers=header)
    else:
        req = requests.get(url=url)
    file = open(".temp.txt", 'w')
    file.write(req.text)
    file.close()
    sed = "sed -i 's+" + '"' + r"+\n+g' .temp.txt"
    subprocess.call(sed, shell=True)
    cat = f"cat .temp.txt | grep '{domain}' | cut -d '" + '"' + f"' -f 2 > {domain}_cert_transparent.txt"
    subprocess.call(cat, shell=True)
    sed = r"sed -i 's+*.++g' .temp.txt"
    subprocess.call(sed, shell=True)
    cat = f"cat .temp.txt | grep '{domain}' | cut -d '" + '"' + f"' -f 2 > {domain}_clean_cert_transparent.txt"
    subprocess.call(cat, shell=True)
    clean = "rm .temp.txt"
    subprocess.call(clean, shell=True)


def sectrails(domain):
    if config.sec_trail != "":
        url = "https://api.securitytrails.com/v1/domain/nucor.com/subdomains?children_only=false&include_inactive=true"

        headers = {
            "accept": "application/json",
            "APIKEY": f"{config.sec_trail}"
        }

        response = requests.get(url, headers=headers)
        jdata = json.loads(response.text)
        count = jdata['subdomain_count']
        doc = ""
        for i in range(0, count):
            data = jdata['subdomains'][i]
            doc += data
        file = open(f"{domain}_clean_sectrails.txt", 'w')
        file.write(doc)
        file.close()


def wayback(sites):
    response = requests.get("https://archive.org/wayback/available?url=" + sites)
    json_data = json.loads(response.text)
    try:
        x = json_data["archived_snapshots"]["closest"]["status"]
        if x == "200":
            print(GREEN + "[+] SUCCESS " + sites + ENDC)
            y = json_data["archived_snapshots"]["closest"]["url"]
            z: object = json_data["archived_snapshots"]["closest"]["timestamp"]

            input_2 = "echo ' " + sites + " is on the way back machine:  " + y + " with a last saved on: " + z + " ' >> " + domain + "_wayback_scan.txt"
            subprocess.call(input_2, shell=True)

    except:
        pass


def scandns(sites):
    if deep:
        bar3.next()

    isp = {"23.202.231.169", "23.221.222.250"}
    ddns = {'.herokudns.com', ".herokuapp.com", ".herokussl.com", ".azurewebsites.net", ".cloudapp.net",
            ".azure-api.net", ".trafficmanager.net", ".azureedge.net", ".cloudapp.azure.com", ".cloudfront.net",
            ".s3.amazonaws.com", ".awsptr.com", ".elasticbeanstalk.com", ".uservoice.com", ".unbouncepages.com",
            ".ghs.google.com", ".ghs.googlehosted.com", ".ghs-ssl.googlehosted.com", ".github.io", ".www.gitbooks.io",
            ".sendgrid.net", ".feedpress.me", ".fastly.net", ".webflow.io", ".proxy.webflow.com", ".helpscoutdocs.com",
            ".readmessl.com", ".desk.com", ".zendesk.com", ".mktoweb.com", ".wordpress.com", ".wpengine.com",
            ".cloudflare.net", ".netlify.com", ".bydiscourse.com", ".netdna-cdn.com", ".pageserve.co",
            ".pantheonsite.io", ".arlo.co", ".apigee.net", ".pmail5.com", ".cm-hosting.com",
            ".ext-cust.squarespace.com",
            ".ext.squarespace.com", ".www.squarespace6.com", ".locationinsight.com", ".helpsite.io",
            ".saas.moonami.com",
            ".custom.bnc.lt", ".qualtrics.com", ".dotcmscloud.net", ".dotcmscloud.com", ".knowledgeowl.com",
            ".atlashost.eu", "headwayapp.co", ".domain.pixieset.com", ".cname.bitly.com", ".awmdm.com", ".meteor.com",
            ".postaffiliatepro.com", ".na.iso.postaffiliatepro.com", ".copiny.com", ".kxcdn.com", ".phs.getpostman.com",
            ".appdirect.com", ".streamshark.io", ".ethosce.com", ".custhelp.com", ".onelink-translations.com",
            ".mashery.com", ".edgesuite.net", ".akadns.net", ".edgekey.net", '.akamaiedge.net', ".edgekey-staging.net",
            ".lldns.net", ".edgecastcdn.net", "centercode.com", ".jivesoftware.com", ".cvent.com", ".covisint.com",
            ".digitalrivercontent.net", ".akahost.net", ".connectedcommunity.org", ".lithium.com", ".sl.smartling.com",
            ".pfsweb.com", ".bsd.net", ".vovici.net", ".extole.com", ".ent-sessionm.com", ".eloqua.com",
            ".inscname.net",
            ".insnw.net", ".2o7.net", ".wnmh.net", ".footprint.net", ".llnwd.net", ".cust.socrata.net", ".scrool.se",
            ".phenompeople.com", ".investis.com", ".skilljar.com", ".imomentous.com", ".cleverbridge.com", ".insnw.net",
            ".sailthru.com", ".static.captora.com", ".q4web.com", ".omtrdc.net", ".devzing.com", ".pphosted.com",
            ".securepromotion.com", ".getbynder.com", ".certain.com", ".certainaws.com", ".eds.com", ".bluetie.com",
            ".relayware.com", ".yodlee.com", ".mrooms.net", ".ssl.cdntwrk.com", ".secure.gooddata.com", ".deltacdn.net",
            ".happyfox.com", ".proformaprostores.com", ".yext-cdn.com", ".edgecastdns.net", ".ecdns.net"}
    q = dns.resolver.resolve(sites, 'A')
    for rname in q:
        name = rname.to_text()
        if name in isp:
            pass
        else:
            with open(domain + "_subdomain_scan.txt") as file:
                if sites in file.read():
                    pass
                else:
                    print("[+] Subdomain:" + sites + " : IP being: " + name + "\n")
                    up = "echo 'Subdomain Found!:  " + sites + " with the IP of: " + name + r" \n ' >> ./" + domain + "_subdomain_scan.txt"
                    subprocess.call(up, shell=True)
                    add_subs = f"echo '{sites}'  >> ./{domain}_subdomains.txt"
                    subprocess.call(add_subs, shell=True)
                    if sites not in site2:
                        current = sites[:]
                        site2.append(current)
                    if name not in ips:
                        current = name[:]
                        ips.append(current)
                    q = dns.resolver.resolve(sites, 'CNAME')
                    for bong in q:
                        c_val = str(bong.target)
                        print(GREEN + "\n[+] The CNAME for " + sites + " is: " + c_val + ENDC)
                        inputfile = "echo '  CNAME Results for " + sites + " is:  " + c_val + r" \n' >> ./" + domain + "_subdomain_scan.txt"
                        subprocess.call(inputfile, shell=True)
                        for d in ddns:
                            if d in c_val:
                                print(
                                    ERROR + "\n\t This subdomain may be vulnerable to dangling DNS pointers, manually verify. \n\t" + c_val + " : " + d + " : Subdomain: " + sites + "\n\n" + ENDC)
                                inputfile = "echo '  CNAME could be vulnerable to dangling DNS " + sites + " is:  " + c_val + " Which is connected to known Dangling DNS source: " + d + r"  you should check on that! \n' >> ./" + domain + "_subdomain_scan.txt "
                                subprocess.call(inputfile, shell=True)

def shodan_scan(ips):
    no_ip = {"127.0.0.1"}
    for ip in ips:
        if ip not in no_ip:
            try:
                api = Shodan(config.s_api_key)
                data = api.search(ip)
                file = shodan_folder + "/" + ip + "_shodan_scan.txt"
                print(BLUE + "[+] -- Shodan Scan on - " + WHITE + BOLD + ip + ENDC)
                file1 = 'Here is the Shodan scan results for {}\n'.format(ip)
                file1 += 'Take a look at all of the data. You might find something cool! \n'
                file1 += '------------------------------------\n'
                file1 += '------------------------------------\n'
                dat = json.dumps(data)
                file1 += "{}".format(dat)
                file1 += "\n\n*************************MARANTRAL******************************\n\n"
                filewrite = open(file, "w")
                filewrite.write(file1)
                filewrite.close()
                sed = rf"sed -i 's+,+\n+g' {file}"
                subprocess.call(sed, shell=True)

            except shodan.APIError as e:
                print("\nThere was an Error: ")
                print(e)
                pass


def add_file_content(ns):

    file = open("./lib/" + ns)
    for line in file:
        bar.next()
        current = line.strip()
        if current not in bf_doc:
            bf_doc.append(current)
    file.close()


def create_domain(subdomain):

    site = subdomain + "." + domain
    if site not in sites:
        current = site[:]
        sites.append(current)
    bar2.next()


def create_deep(dom):

    for subdomain in subdomains:
        site = subdomain + "." + dom
        if site not in new_sites:
            current = site[:]
            new_sites.append(current)

    if additional:
        for subdomain in add:
            site = subdomain + "." + dom
            if site not in new_sites:
                current = site[:]
                new_sites.append(current)
    bar_deep.next()


def shodan_scan_domain():
    for site in site2:
        try:
            api = Shodan(config.s_api_key)
            data = api.search(site)
            file = shodan_folder + "/" + site + "_shodan_scan.txt"
            print(BLUE + "[+] -- Shodan Scan on - " + WHITE + BOLD + site + ENDC)
            file1 = 'Here is the Shodan scan results for {}\n'.format(site)
            file1 += 'Take a look at all of the data. You might find something cool! \n'
            file1 += '------------------------------------\n'
            file1 += '------------------------------------\n'
            dat = json.dumps(data)
            file1 += "{}".format(dat)
            file1 += "\n\n*************************MARANTRAL******************************\n\n"
            filewrite = open(file, "w")
            filewrite.write(file1)
            filewrite.close()
            sed = rf"sed -i 's+,+\n+g' {file}"
            subprocess.call(sed, shell=True)
            time.sleep(1)

        except shodan.APIError as e:
            print("\nThere was an Error: ")
            print(e)
            pass


def main():
    global domain, subdomains
    global shodan_folder
    global bar, bar2, bar3, bar_deep
    global deep, additional, add
    deep = False

    print(BOLD + ERROR + r"""
                 _____       _     _____                  _             _                  
                / ____|     | |   |  __ \                (_)           | |
               | (___  _   _| |__ | |  | | ___  _ __ ___  _ _ __   __ _| |
                \___ \| | | | '_ \| |  | |/ _ \| '_ ` _ \| | '_ \ / _` | |
                ____) | |_| | |_) | |__| | (_) | | | | | | | | | | (_| | |
               |_____/ \__,_|_.__/|_____/ \___/|_| |_| |_|_|_| |_|\__,_|_|
                                                           

    """ + ENDC)

    print(GREEN + """
                        _____             __         __  ___      
                       / ___/______ ___ _/ /____ ___/ / / _ )__ __
                      / /__/ __/ -_) _ `/ __/ -_) _  / / _  / // /
                      \___/_/  \__/\_,_/\__/\__/\_,_/ /____/\_, / 
                                                           /___/  
                 __  ___                   __           __  ________      
                /  |/  /__ ________ ____  / /________ _/ / /_  __/ /  ___ 
               / /|_/ / _ `/ __/ _ `/ _ \/ __/ __/ _ `/ /   / / / _ \/ -_)
              /_/  /_/\_,_/_/  \_,_/_//_/\__/_/  \_,_/_/   /_/ /_//_/\__/ 

                            __  ___          __           ____
                           /  |/  /__ ____  / /________  / / /
                          / /|_/ / _ `/ _ \/ __/ __/ _ \/ / / 
                         /_/  /_/\_,_/_//_/\__/_/  \___/_/_/  

                                      Version 0.9 
    """ + ENDC)

    print(BLUE + "\n\tWhen defining the domain to be scanned, use the parent domain.")
    print("\tLike: 'google.com' or 'company.org'\n")
    print("\t\t\tHAPPY HUNTING!!!'\n\n" + ENDC)

    domain = args.domain

    file = open("./lib/subdomains-10000.txt")
    content = file.read()
    subdomains = content.splitlines()
    file.close()
    bar = IncrementalBar('Loading values', max=216352)
    smate(domain)
    file = open(f"{domain}_clean_cert_transparent.txt", 'r')
    for l in file:
        current = l.strip()
        if current != "":
            if current not in sites:
                sites.append(current)
    file.close()

    cn_scan(domain)
    file = open(f"{domain}_clean_crt_scan.txt", 'r')
    for l in file:
        current = l.strip()
        if current != "":
            if current not in sites:
                sites.append(current)
    file.close()
    sectrails(domain)
    file = open(f"{domain}_clean_sectrails.txt", 'r')
    for l in file:
        current = l.strip()
        if current != "":
            if current not in sites:
                sites.append(current)
    file.close()
    ht_scan(domain)
    file = open(f"{domain}_clean_hackertarget_scan.txt", 'r')
    for l in file:
        current = l.strip()
        if current != "":
            if current not in sites:
                sites.append(current)
    file.close()

    site_1 = "https://web.archive.org/cdx/search/cdx?url=*." + domain + "/*&output=text&fl=original&collapse=urlkey"
    response_2 = requests.get(site_1)
    response_fin = response_2.text
    file = open(domain + "_way_osint.txt", "w")
    file.write(response_fin)
    file.close()
    clean = f"cat {domain}_way_osint.txt | cut -d '/' -f 3 | cut -d ':' -f 1 | sort | uniq > {domain}_way_clean.txt"
    subprocess.call(clean, shell=True)
    file = open(f"{domain}_way_clean.txt", 'r')
    for l in file:
        current = l.strip()
        if current != "":
            if current not in sites:
                sites.append(current)
    file.close()

    if args.brute:
        names = ['xaa', 'xab', 'xac', 'xad']
        print("\n\t----Adding values----\n")
        with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
            executor.map(add_file_content, names)
        names.clear()
    try:
        file = open(args.sub)
        content = file.read()
        add = content.splitlines()
        file.close()
        additional = True
    except:
        additional = False
        pass
    for subdomain in subdomains:
        site = subdomain + "." + domain
        if site not in sites:
            current = site[:]
            sites.append(current)
    if args.brute:
        bar2 = IncrementalBar('Creating possible subdomains', max=216352)
        print("\n\n\t----Creating domain possibilities----\n")
        with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
            executor.map(create_domain, bf_doc)
    if additional:
        for subdomain in add:
            site = subdomain + "." + domain
            if site not in sites:
                current = site[:]
                sites.append(current)

    print(GREEN + "\n\n\t-----Conducting DNS Subdomain Scan-----\n" + ENDC)
    up = r"echo '----- Subdomain Scan of " + domain + r" ----- \n\n' > ./" + domain + "_subdomain_scan.txt"
    subprocess.call(up, shell=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
        executor.map(scandns, sites)
    if args.brute:
        sites.clear()
        bf_doc.clear()
        print("\n\t----Adding values----\n")
        names = ['xae', 'xaf', 'xag', 'xah', 'xai']
        bar = IncrementalBar('Loading values', max=256000)
        with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
            executor.map(add_file_content, names)
        names.clear()
        bar2 = IncrementalBar('Creating possible subdomains', max=256000)
        print("\n\n\t----Creating domain possibilities----\n")
        with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
            executor.map(create_domain, bf_doc)
        print(GREEN + "\n\n\t-----Conducting DNS Subdomain Scan-----\n" + ENDC)
        with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
            executor.map(scandns, sites)

        sites.clear()
        bf_doc.clear()
        print("\n\t----Adding values----\n")
        names = ['xaj', 'xak', 'xal', 'xam', 'xan']
        bar = IncrementalBar('Loading values', max=256000)
        with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
            executor.map(add_file_content, names)
        names.clear()
        bar2 = IncrementalBar('Creating possible subdomains', max=256000)
        print("\n\n\t----Creating domain possibilities----\n")
        with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
            executor.map(create_domain, bf_doc)
        print(GREEN + "\n\n\t-----Conducting DNS Subdomain Scan-----\n" + ENDC)
        with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
            executor.map(scandns, sites)
        sites.clear()
        bf_doc.clear()
        print("\n\t----Adding values----\n")
        names = ['xao', 'xap', 'xaq', 'xar', 'xas']
        bar = IncrementalBar('Loading values', max=256000)
        with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
            executor.map(add_file_content, names)
        names.clear()
        bar2 = IncrementalBar('Creating possible subdomains', max=256000)
        print("\n\n\t----Creating domain possibilities----\n")
        with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
            executor.map(create_domain, bf_doc)
        print(GREEN + "\n\n\t-----Conducting DNS Subdomain Scan-----\n" + ENDC)
        with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
            executor.map(scandns, sites)
        sites.clear()
        bf_doc.clear()
        print("\n\t----Adding values----\n")
        names = ['xat', 'xau', 'xav', 'xaw', 'xax']
        bar = IncrementalBar('Loading values', max=256000)
        with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
            executor.map(add_file_content, names)
        names.clear()
        bar2 = IncrementalBar('Creating possible subdomains', max=256000)
        print("\n\n\t----Creating domain possibilities----\n")
        with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
            executor.map(create_domain, bf_doc)
        print(GREEN + "\n\n\t-----Conducting DNS Subdomain Scan-----\n" + ENDC)
        with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
            executor.map(scandns, sites)
        sites.clear()
        bf_doc.clear()
        print("\n\t----Adding values----\n")
        names = ['xay', 'xaz', 'xba', 'xbb', 'xbc']
        bar = IncrementalBar('Loading values', max=256000)
        with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
            executor.map(add_file_content, names)
        names.clear()
        bar2 = IncrementalBar('Creating possible subdomains', max=256000)
        print("\n\n\t----Creating domain possibilities----\n")
        with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
            executor.map(create_domain, bf_doc)
        print(GREEN + "\n\n\t-----Conducting DNS Subdomain Scan-----\n" + ENDC)
        with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
            executor.map(scandns, sites)
        sites.clear()
        bf_doc.clear()
        print("\n\t----Adding values----\n")
        names = ['xbd', 'xbe', 'xbf', 'xbg', 'xbh']
        bar = IncrementalBar('Loading values', max=256000)
        with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
            executor.map(add_file_content, names)
        names.clear()
        bar2 = IncrementalBar('Creating possible subdomains', max=256000)
        print("\n\n\t----Creating domain possibilities----\n")
        with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
            executor.map(create_domain, bf_doc)
        print(GREEN + "\n\n\t-----Conducting DNS Subdomain Scan-----\n" + ENDC)
        with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
            executor.map(scandns, sites)
        sites.clear()
        bf_doc.clear()
        print("\n\t----Adding values----\n")
        names = ['xbi', 'xbj', 'xbk', 'xbl', 'xbm']
        bar = IncrementalBar('Loading values', max=256000)
        with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
            executor.map(add_file_content, names)
        names.clear()
        bar2 = IncrementalBar('Creating possible subdomains', max=256000)
        print("\n\n\t----Creating domain possibilities----\n")
        with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
            executor.map(create_domain, bf_doc)
        print(GREEN + "\n\n\t-----Conducting DNS Subdomain Scan-----\n" + ENDC)
        with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
            executor.map(scandns, sites)
        sites.clear()
        bf_doc.clear()
        print("\n\t----Adding values----\n")
        names = ['xbn', 'xbo', 'xbp']
        bar = IncrementalBar('Loading values', max=133100)
        with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
            executor.map(add_file_content, names)
        names.clear()
        bar2 = IncrementalBar('Creating possible subdomains', max=133100)
        print("\n\n\t----Creating domain possibilities----\n")
        with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
            executor.map(create_domain, bf_doc)
        print(GREEN + "\n\n\t-----Conducting DNS Subdomain Scan-----\n" + ENDC)
        length = len(sites)

        with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
            executor.map(scandns, sites)

    if args.deep:
        length = len(site2)

        if length <= 10:
            bar_deep = IncrementalBar('Creating list for Deep Scan:', max=length)
            with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
                executor.map(create_deep, site2)
            bar_deep.finish()
            print(GREEN + "\n\n\t-----Conducting DEEPER DNS Subdomain Scan-----\n" + ENDC)
            length_1 = len(new_sites)
            bar3 = IncrementalBar('Deep Scanning Subdomains:', max=length_1)
            deep = True
            with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
                executor.map(scandns, new_sites)
            bar3.finish()
            new_sites.clear()

        elif length <= 120:
            val_num = length // 5
            sub_list = [site2[x:x + val_num + 1] for x in range(0, length, val_num)]
            amount = [0, 1, 2, 3, 4, 5]
            for i in amount:
                val_sub = len(sub_list[i])
                bar_deep = IncrementalBar('Creating list for Deep Scan:', max=val_sub)
                with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
                    executor.map(create_deep, sub_list[i])
                bar_deep.finish()
                print(GREEN + "\n\n\t-----Conducting DEEPER DNS Subdomain Scan-----\n" + ENDC)
                length_1 = len(new_sites)
                bar3 = IncrementalBar('Deep Scanning Subdomains:', max=length_1)
                deep = True
                with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
                    executor.map(scandns, new_sites)
                bar3.finish()
                new_sites.clear()
        elif length <= 400:
            val_num = length // 20
            sub_list = [site2[x:x + val_num + 1] for x in range(0, length, val_num)]

            amount = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19]
            for i in amount:
                val_sub = len(sub_list[i])
                bar_deep = IncrementalBar('Creating list for Deep Scan:', max=val_sub)
                with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
                    executor.map(create_deep, sub_list[i])
                bar_deep.finish()
                print(GREEN + "\n\n\t-----Conducting DEEPER DNS Subdomain Scan-----\n" + ENDC)
                length_1 = len(new_sites)
                bar3 = IncrementalBar('Deep Scanning Subdomains:', max=length_1)
                deep = True
                with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
                    executor.map(scandns, new_sites)
                bar3.finish()
                new_sites.clear()

        else:
            print('Too many subdomains- Skipping deep scan.')
            pass





    if args.way_history:
        print(BLUE + "\n\t-----Conducting Wayback Machine Scan-----\n" + ENDC)
        up = r"echo '----- Wayback scan of " + domain + r" ----- \n\n' > ./" + domain + "_wayback_scan.txt"
        subprocess.call(up, shell=True)
        with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
            executor.map(wayback, site2)
    if args.way_osint:
        print(GREEN + "\n\t-----We are looking for interesting urls within the Wayback Machine for " + domain + "-----\n" + ENDC)

        site_1 = "https://web.archive.org/cdx/search/cdx?url=*." + domain + "/*&output=text&fl=original&collapse=urlkey"
        response_2 = requests.get(site_1)

        pars = ["user=", "pass=", "password=", "pword=", "username=", "token=", "secret=",
                "email=", "admin=", "administrator=", "jsession=", "jsessionid=", "userid=", ]

        for p in pars:
            for line in response_2.iter_lines():
                if p in line.decode("utf-8").lower():
                    print(BLUE + "\n\tPotential interesting " + p + " parameter found: " + BOLD + ERROR + line.decode("utf-8") + ENDC)

        print(BLUE + "\n\tThere might be other interesting values within the parameters that we might not have found "
                     "automatically.\n\tTake a look manually!" + ENDC)

    if args.shodan:
        shodan_folder = domain + "_Shodan"
        if config.s_api_key != "":
            try:
                os.mkdir(shodan_folder)
            except:
                pass
            print(GREEN + "\n\t-----Conducting Shodan Scan-----\n" + ENDC)
            shodan_scan(ips)
            shodan_scan_domain()


    print(BOLD + "\n\nThanks for using SubDominal!\n\n" + ENDC)


# call main() function
if __name__ == '__main__':
    main()
