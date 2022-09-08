import dns.resolver
import subprocess
import concurrent.futures
import json
import requests
from shodan import Shodan
import shodan
import os
import argparse


parser = argparse.ArgumentParser(description='Subdomain Eunmeration tool')
parser.add_argument('--domain', '-d', dest="domain", type=str, required=True,
                    help='When defining the domain to be scanned, use the parent domain.\n\tLike: google.com or '
                         'company.org')
parser.add_argument('--sub', '-s', dest="sub", type=str,
                    help='Additonal subdomain list.')
parser.add_argument('--brute', '-b', default=False, action="store_true")
parser.add_argument('--deep', '-dp', default=False, action="store_true")

args = parser.parse_args()


### CONFIG API Keys ###
#### Shodan API KEY GOES HERE ###
s_api_key = ""
###################


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

def shodan_scan(ipss):
    no_ip = {"127.0.0.1"}
    for ip in ips:
        if ip not in no_ip:
            try:
                api = Shodan(s_api_key)
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
                file1 += "\n\n*************************MARANTRAL******************************\n\n"
                file1 += "\n\n*************************MARANTRAL******************************\n\n"
                filewrite = open(file, "w")
                filewrite.write(file1)
                filewrite.close()

            except shodan.APIError as e:
                print("\nThere was an Error: ")
                print(e)
                pass



def shodan_scan_domain(sites):
    for site in site2:
        try:
            api = Shodan(s_api_key)
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
            file1 += "\n\n*************************MARANTRAL******************************\n\n"
            file1 += "\n\n*************************MARANTRAL******************************\n\n"
            filewrite = open(file, "w")
            filewrite.write(file1)
            filewrite.close()

        except shodan.APIError as e:
            print("\nThere was an Error: ")
            print(e)
            pass


def main():
    global domain
    global shodan_folder

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

                                      Version 0.4 
    """ + ENDC)

    print(BLUE + "\n\tWhen defining the domain to be scanned, use the parent domain.")
    print("\tLike: 'google.com' or 'company.org'\n\n" + ENDC)

    domain = args.domain

    file = open("./lib/subdomains-10000.txt")
    content = file.read()
    subdomains = content.splitlines()
    file.close()
    print("got past one")
    names = ['xaa', 'xab', 'xac', 'xad', 'xae', 'xaf', 'xag', 'xah', 'xai', 'xaj', 'xak', 'xal', 'xam',
             'xan', 'xao', 'xap', 'xaq', 'xar', 'xas', 'xat', 'xau', 'xav', 'xaw', 'xax']
    bf_doc = []
    for ns in names:
        file = open("./lib/" + ns)
        for line in file:
            current = line.strip()
            if current not in bf_doc:
                bf_doc.append(current)
        file.close()

    print("got past two")
    try:
        file = open(args.sub)
        content = file.read()
        bf_doc = content.splitlines()
        file.close()
        add = []
        file.close()
        aditional = True
        print("got past 3")
    except:
        aditional = False
        pass
    for subdomain in subdomains:
        site = subdomain + "." + domain
        if site not in sites:
            current = site[:]
            sites.append(current)
    if args.brute:
        for subdomain in bf_doc:
            site = subdomain + "." + domain
            if site not in sites:
                current = site[:]
                sites.append(current)
    if aditional:
        for subdomain in add:
            site = subdomain + "." + domain
            if site not in sites:
                current = site[:]
                sites.append(current)
    print("got past 4")

    print(GREEN + "\n\t-----Conducting DNS Subdomain Scan-----\n" + ENDC)
    up = r"echo '----- Subdomain Scan of " + domain + r" ----- \n\n' > ./" + domain + "_subdomain_scan.txt"
    subprocess.call(up, shell=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
        executor.map(scandns, sites)

    if args.deep:
        new_sites = []
        for dom in site2:
            for subdomain in subdomains:
                site = subdomain + "." + dom
                if site not in new_sites:
                    current = site[:]
                    new_sites.append(current)

            for subdomain in bf_doc:
                site = subdomain + "." + dom
                if site not in new_sites:
                    current = site[:]
                    new_sites.append(current)

        print(GREEN + "\n\t-----Conducting DEEPER DNS Subdomain Scan-----\n" + ENDC)
        with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
            executor.map(scandns, new_sites)

    print(BLUE + "\n\t-----Conducting Wayback Machine Scan-----\n" + ENDC)
    up = r"echo '----- Wayback scan of " + domain + r" ----- \n\n' > ./" + domain + "_wayback_scan.txt"
    subprocess.call(up, shell=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
        executor.map(wayback, site2)

    print(GREEN + "\n\t-----We are looking for interesting urls within the Wayback Machine for " + domain + "-----\n" + ENDC)
    site_1 = "https://web.archive.org/cdx/search/cdx?url=*." + domain + "/*&output=text&fl=original&collapse=urlkey"
    response_2 = requests.get(site_1)
    response_fin = response_2.text
    file = open(domain + "_way_osint.txt", "w")
    file.write(response_fin)
    file.close()

    pars = ["user=", "pass=", "password=", "pword=", "username=", "token=", "secret=",
            "email=", "admin=", "administrator=", "jsession=", "jsessionid=", "userid=", ]

    for p in pars:
        for line in response_2.iter_lines():
            if p in line.decode("utf-8").lower():
                print(BLUE + "\n\tPotential interesting " + p + " parameter found: " + BOLD + ERROR + line.decode("utf-8") + ENDC)

    print(BLUE + "\n\tThere might be other interesting values within the parameters that we might not have found "
                 "automatically.\n\tTake a look manually!" + ENDC)

    shodan_folder = domain + "_Shodan"
    if s_api_key != "":
        try:
            os.mkdir(shodan_folder)
        except:
            pass
        print(GREEN + "\n\t-----Conducting Shodan Scan-----\n" + ENDC)
        shodan_scan(ips)
        shodan_scan_domain(site2)


    print("\n\tOutput files are: \n\t" + GREEN + domain + "_subdomain_scan.txt \n\t" + domain
          + "_wayback_scan.txt \n\t" + domain + "_way_osint.txt\n" + "\n\n\tShodan scans in: " + shodan_folder + ENDC)
    print(BOLD + "\n\nThanks for using SubDominal!\n\n" + ENDC)


# call main() function
if __name__ == '__main__':
    main()
