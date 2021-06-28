import dns.resolver
import subprocess
import concurrent.futures

BLUE = '\033[94m'
GREEN = '\033[92m'
WARNING = '\033[93m'
WHITE = '\033[97m'
ERROR = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'

def scandns(sites):
    isp = {"23.202.231.169", "23.221.222.250"}
    ddns = {'.herokudns.com', ".herokuapp.com", "herokussl.com", ".azurewebsites.net", ".cloudapp.net",
            ".azure-api.net", ".trafficmanager.net", ".azureedge.net", ".cloudapp.azure.com", ".cloudfront.net",
            ".s3.amazonaws.com", ".awsptr.com", ".elasticbeanstalk.com", ".uservoice.com", "unbouncepages.com",
            "ghs.google.com", "ghs.googlehosted.com", ".ghs-ssl.googlehosted.com", ".github.io", "www.gitbooks.io",
            "sendgrid.net", ".feedpress.me", ".fastly.net", ".webflow.io", "proxy.webflow.com", ".helpscoutdocs.com",
            ".readmessl.com", ".desk.com", ".zendesk.com", ".mktoweb.com", ".wordpress.com", ".wpengine.com",
            ".cloudflare.net", ".netlify.com", ".bydiscourse.com", ".netdna-cdn.com", ".pageserve.co",
            ".pantheonsite.io", ".arlo.co", ".apigee.net", ".pmail5.com", ".cm-hosting.com", "ext-cust.squarespace.com",
            "ext.squarespace.com", "www.squarespace6.com", ".locationinsight.com", ".helpsite.io", "saas.moonami.com",
            "custom.bnc.lt", ".qualtrics.com", ".dotcmscloud.net", ".dotcmscloud.com", ".knowledgeowl.com",
            ".atlashost.eu", "headwayapp.co", "domain.pixieset.com", "cname.bitly.com", ".awmdm.com", ".meteor.com",
            ".postaffiliatepro.com", "na.iso.postaffiliatepro.com", ".copiny.com", ".kxcdn.com", "phs.getpostman.com",
            ".appdirect.com", ".streamshark.io", ".ethosce.com", ".custhelp.com", ".onelink-translations.com",
            ".mashery.com", ".edgesuite.net", ".akadns.net", ".edgekey.net", 'akamaiedge.net', ".edgekey-staging.net",
            ".lldns.net", ".edgecastcdn.net", "centercode.com", ".jivesoftware.com", ".cvent.com", ".covisint.com",
            ".digitalrivercontent.net", ".akahost.net", ".connectedcommunity.org", ".lithium.com", ".sl.smartling.com",
            "pfsweb.com", ".bsd.net", ".vovici.net", ".extole.com", ".ent-sessionm.com", ".eloqua.com", ".inscname.net",
            "insnw.net", ".2o7.net", ".wnmh.net", ".footprint.net", ".llnwd.net", ".cust.socrata.net", ".scrool.se",
            ".phenompeople.com", ".investis.com", ".skilljar.com", ".imomentous.com", ".cleverbridge.com", ".insnw.net",
            "sailthru.com", "static.captora.com", ".q4web.com", ".omtrdc.net", ".devzing.com", ".pphosted.com",
            ".securepromotion.com", ".getbynder.com", ".certain.com", ".certainaws.com", ".eds.com", ".bluetie.com",
            ".relayware.com", ".yodlee.com", ".mrooms.net", "ssl.cdntwrk.com", "secure.gooddata.com", ".deltacdn.net",
            ".happyfox.com", ".proformaprostores.com", ".yext-cdn.com", ".edgecastdns.net", ".ecdns.net"}
    q = dns.resolver.resolve(sites, 'A')
    for rname in q:
        name = rname.to_text()
        if name in isp:
            pass
        else:
            print("[+] Subdomain:" + sites + " : IP being: " + name + "\n")
            up = "echo 'Subdomain Found!!:  " + sites + " with the IP of: " + name + r" \n ' >> ./" + domain + "_subdomain_Scan.txt"
            subprocess.call(up, shell=True)

            q = dns.resolver.resolve(sites, 'CNAME')
            for bong in q:
                c_val = str(bong.target)
                print("\n[+] The CNAME for " + sites + " is: " + c_val)
                inputfile = "echo '  CNAME Results for " + sites + " is:  " + c_val + r" \n' >> ./" + domain + "_subdomain_Scan.txt"
                subprocess.call(inputfile, shell=True)
                for d in ddns:
                    if d in c_val:
                        print("\n\t!!!!!we might have a dangler!!!!! " + c_val + " : " + d + " : Subdomain: " + sites)
                        inputfile = "echo '  CNAME could be vulnerable to dangling DNS " + sites + " is:  " + c_val + " Which is connected to known Dangling DNS source: " + d + r"  you should check on that! \n' >> ./" + domain + "_subdomain_Scan.txt "
                        subprocess.call(inputfile, shell=True)


def main():
    global domain

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

                                      Version 0.1 
    """ + ENDC)



    domain = input("what is the domain to be scanned?: ").strip()

    file = open("./lib/subdomains-10000.txt")
    content = file.read()
    subdomains = content.splitlines()
    sites = []
    for subdomain in subdomains:
        site = subdomain + "." + domain
        if site not in sites:
            current = site[:]
            sites.append(current)

    up = r"echo '----- SubDomain Scan of " + domain + r" ----- \n\n' > ./" + domain + "_subdomain_Scan.txt"
    subprocess.call(up, shell=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=None) as executor:
        executor.map(scandns, sites)


# call main() function
if __name__ == '__main__':
    main()
