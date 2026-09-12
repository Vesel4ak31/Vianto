import re
import argparse
import requests
import time
from colorama import Fore,Back,Style,init
from random import SystemRandom

from config.config import config_matches
from config.title import title

import vt
import sys
import os
from pathlib import Path
import datetime
from math import ceil
from hashlib import md5,sha256,sha512
init(True)


class Vianto:
    def __init__(self,
                 path : str,
                 virus_total="",

                skip_file_options_check = False,
                skip_malware_check= False,
                skip_file_check= False,
                skip_file_info_check= False,
                timeout=0.0,
                output_file=False,
                random_timeout="",
                jitter=0.0):

        self.path = path
        self.folder = None

        self.lines = None
        self.matches = None 
        self.config = config_matches
        self.timer = time.time()
        self.line_count = 0
        self.total_matches = 0
        self.directory = None
        self.file_path = None
        self.client = None
        self.timeout = timeout
        self.output_file = output_file
        
        self.sha256_hash = sha256()
        self.sha512_hash = sha512()
        self.md5_hash = md5()
        self.sha256_info = None
        self.data = dict()
        self.params_config = ["ipv4 address","ipv6 address","domain","url"]

        self.ips = set()
        self.domains = set()
        self.urls = set()

        self.ip_info = None
        self.domain_info = None
        self.url_info = None

        self.hash_data = None
        self.virus_total_api_key = virus_total

        self.skip_file_options_check = skip_file_options_check
        self.skip_malware_check = skip_malware_check
        self.skip_file_check = skip_file_check
        self.skip_file_info_check = skip_file_info_check
        self.low , self.high = None,None

        self.random_timeout = random_timeout
        self.jitter = jitter

        if self.timeout == 0.0:
            self.timeout = 3.1

        if self.random_timeout:

            self.random_timeout = self.parse_range(random_timeout)

        else:

            self.random_timeout = None

    def parse_range(self, value: str) -> list:

        try:

            self.low , self.high = float(value.split('-')[0]) , float(value.split('-')[1])

            if len(value.split('-')) != 2:

                raise ValueError("Expected format: min-max")
            
            
            if self.low < 0 or self.high < 0:
                raise ValueError("Values must be positive")
            
            if self.low > self.high :

                raise ValueError("Low value cannot be greater than high value")

            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [#] random timeout rande parsed: [{self.low};{self.high}]")
            return [self.low, self.high]
        
        except ValueError as e:

            self.safe_print(self.render_text("!",Back.RED,f"invalid range format: {e} . expected: min-max (e.g., 0.5-2.5)"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [!] invalid range format: {e} . expected: min-max (e.g., 0.5-2.5)")
            sys.exit(1)

    def get_timeout(self) -> float:

        if self.random_timeout:
            rto = SystemRandom().uniform(self.random_timeout[0],self.random_timeout[1]) + self.jitter 
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [#] random timeout: {rto}")
            return rto
        
        return self.timeout + self.jitter

    def logging(self, string : str) -> bool:
    
        if not self.output_file:  
            return False
        
        try:
    
            with open(self.output_file,"a", encoding="utf-8") as log_file:
                log_file.write(f"{string}\n")
    
            return True
            
        except Exception:
    
            return False
        

    def clear_hashes(self) -> bool:

        try:

            self.hash_data = None
            self.sha256_hash = sha256()
            self.sha512_hash = sha512()
            self.md5_hash = md5()
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [#] clear hashes")
            return True

        except Exception as e:
                      
                print(self.render_text("!",Style.BRIGHT + Fore.RED,f"hash clear error: {Style.BRIGHT + Fore.WHITE + str(e) + Style.RESET_ALL}"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [!] hash clear error {e}")
                time.sleep(self.get_timeout())
                      
    def render_info(self,text : list) -> bool:

        try:

            for t in text:
                print(self.render_text("#",Style.BRIGHT + Fore.YELLOW,t))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [#] render info: [#] {t}")

            return True

        except Exception as e:
                              
            print(self.render_text("!",Style.BRIGHT + Fore.RED,f"render info error: {Style.BRIGHT + Fore.WHITE + str(e) + Style.RESET_ALL}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [!] render info error: {e}")
            time.sleep(self.get_timeout())
            return False

    def hash_file(self,connector : any) -> None:


        try:
            self.clear_hashes()
            with open(self.path,"rb") as file:
                   
                   while True:

                    self.hash_data = file.read(65536)
                    if not self.hash_data:
                            break

                    connector.update(self.hash_data)

            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [#] hash file: {connector.hexdigest()}")
            return connector.hexdigest()

        except Exception as e:
              
            print(self.render_text("!",Style.BRIGHT + Fore.RED,f"hash file error: {Style.BRIGHT + Fore.WHITE + str(e) + Style.RESET_ALL}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [!] hash file error: {e}")
            time.sleep(self.get_timeout())

    def scan_ip(self,ip_address : str) -> bool:

        try:

            self.client = vt.Client(self.virus_total_api_key)
            self.ip_info = self.client.get_object(f"/ip_addresses/{ip_address}")
            print(f"{self.render_text("#",Style.BRIGHT + Fore.BLUE,f"check ip address: {ip_address}")}")
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [#] check ip address: {ip_address}")
            self.render_info([f"{self.ip_info.last_analysis_stats["malicious"]} antivirus programs flagged this IP address as malicious",f"{self.ip_info.last_analysis_stats["suspicious"]} antivirus programs did not assign an intermediate status to this IP address",f"{self.ip_info.last_analysis_stats["undetected"]} antivirus programs found nothing suspicious",f"{self.ip_info.last_analysis_stats["harmless"]} antivirus programs mark this IP address as 'completely safe'",f"{self.ip_info.last_analysis_stats["timeout"]} antivirus programs returned a timeout error"])
            self.client.close()
            print()
            return True

        except vt.APIError as e:
                
            print(self.render_text("!",Style.BRIGHT + Fore.RED,f"VirusTotal API error: {Style.BRIGHT + Fore.WHITE + str(e) + Style.RESET_ALL}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [!] VirusTotal API error: {e}")
            return False
        
        except Exception as e:
                              
            print(self.render_text("!",Style.BRIGHT + Fore.RED,f"global sort ipv4 error: {Style.BRIGHT + Fore.WHITE + str(e) + Style.RESET_ALL}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [!] global ipv4 error: {e}")
            time.sleep(self.get_timeout())
            return False



    def scan_domain(self,domain : str) -> bool:
    
            try:

                self.client = vt.Client(self.virus_total_api_key)
                self.domain_info = self.client.get_object(f"/domains/{domain}")
                print(f"{self.render_text("#",Style.BRIGHT + Fore.BLUE,f"check domain: {domain}")}")
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [#] check domain: {domain}")
                self.render_info([f"{self.domain_info.last_analysis_stats["malicious"]} antivirus programs flagged this domain as malicious",f"{self.domain_info.last_analysis_stats["suspicious"]} antivirus programs did not assign an intermediate status to this domain",f"{self.domain_info.last_analysis_stats["undetected"]} antivirus programs found nothing suspicious",f"{self.domain_info.last_analysis_stats["harmless"]} antivirus programs mark this domain as 'completely safe'",f"{self.domain_info.last_analysis_stats["timeout"]} antivirus programs returned a timeout error"])
                self.client.close()
                print()
                return True
            
            except Exception as e:
                                  
                print(self.render_text("!",Style.BRIGHT + Fore.RED,f"global sort domain error: {Style.BRIGHT + Fore.WHITE + str(e) + Style.RESET_ALL}"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [!] global sort domain error: {e}")
                time.sleep(self.get_timeout())
                return False

    def scan_url(self,url : str) -> bool:
        
            try:

                self.client = vt.Client(self.virus_total_api_key)
                self.url_info = self.client.scan_url(url,wait_for_completion=True)
                print(f"{self.render_text("#",Style.BRIGHT + Fore.BLUE,f"check url: {url}")}")
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [#] check url: {url}")
                self.render_info([f"{self.url_info.stats["malicious"]} antivirus programs flagged this url as malicious",f"{self.url_info.stats["suspicious"]} antivirus programs did not assign an intermediate status to this url",f"{self.url_info.stats["undetected"]} antivirus programs found nothing suspicious",f"{self.url_info.stats["harmless"]} antivirus programs mark this url as 'completely safe'",f"{self.url_info.stats["timeout"]} antivirus programs returned a timeout error",f"{self.url_info.stats["confirmed_timeout"]} 9 antivirus programs returned a 'confirmed timeout' error",f"{self.url_info.stats["failure"]} antivirus engines returned an error during scanning",f"{self.url_info.stats["type_unsupported"]} antivirus programs failed to scan the object because they do not support this file type"])
                self.client.close()
                print()
                return True
                
            except Exception as e:
                                      
                print(self.render_text("!",Style.BRIGHT + Fore.RED,f"global sort url error: {Style.BRIGHT + Fore.WHITE + str(e) + Style.RESET_ALL}"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [!] global sort url error: {e}")
                time.sleep(self.get_timeout())
                return False
            
    def global_sort(self,param : str,value : str) -> bool:

        try:


            match(param):

                case "ipv4 address":
                    self.ips.add(value)
                    self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [#] add ipv4: {value}")

                case "ipv6 address":
                    self.ips.add(value)
                    self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [#] add ipv6: {value}")

                case "domain":
                    self.domains.add(value)
                    self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [#] add domain {value}")

                case "url":
                    self.urls.add(value)
                    self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [#] add url: {value}")

                case _:
                    pass

            return True
        
        except Exception as e:
                      
            print(self.render_text("!",Style.BRIGHT + Fore.RED,f"global sort error: {Style.BRIGHT + Fore.WHITE + str(e) + Style.RESET_ALL}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [!] global sort error: {e}")
            time.sleep(self.get_timeout())
            return False
              

    def render_text(self, message_type : str , message_type_color , message : str) -> str:
        self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [#] render text: [{message_type}] {message}")
        return "[" + message_type_color + f"{message_type}" + Style.RESET_ALL + "] " + f"{message}" + Style.RESET_ALL


    def malware_check(self,sha256 : str) -> bool:

        try:
            
            self.client = vt.Client(self.virus_total_api_key)
            self.clear_hashes()
            self.sha256_info = self.client.get_object(f"/files/{sha256}")
            print()
            print(f"{self.render_text("#",Style.BRIGHT + Fore.BLUE,f"file malware check")}")
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [#] file malware check")
            self.render_info([f"sha256 hash: {self.sha256_info.sha256}",f"file type tag: {self.sha256_info.type_tag}",f"file size: {self.sha256_info.size} bytes",f"{self.sha256_info.last_analysis_stats["malicious"]} antivirus programs flagged this file as a competitor",f"{self.sha256_info.last_analysis_stats["type-unsupported"]} antivirus programs failed to scan the object because they do not support this file type",f"only {self.sha256_info.last_analysis_stats["undetected"]} antivirus programs found nothing suspicious (the object remained undetected by them)",f"{self.sha256_info.last_analysis_stats["failure"]} antivirus engines returned an error during scanning",f"{self.sha256_info.last_analysis_stats["harmless"]} antivirus mark this file as 'guaranteed safe'",f"{self.sha256_info.last_analysis_stats["suspicious"]} antivirus programs did not assign an intermediate status to this file",f"{self.sha256_info.last_analysis_stats["timeout"]} antivirus programs returned a timeout error"])
            print()
            self.client.close()
            return True

        except vt.APIError as e:
        
                print(self.render_text("!",Style.BRIGHT + Fore.RED,f"VirusTotal API error: {Style.BRIGHT + Fore.WHITE + str(e) + Style.RESET_ALL}"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [!] VirusTotal API error: {e}")
                return False

        except Exception as e:

            print(self.render_text("!",Style.BRIGHT + Fore.RED,f"malware check error: {Style.BRIGHT + Fore.WHITE + str(e) + Style.RESET_ALL}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [!] malware check error: {e}")
            return False

    def file_check(self) -> bool:

        try:
            print(f"{self.render_text("#",Style.BRIGHT + Fore.BLUE,f"file check")}")
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [#] file check")
            time.sleep(self.get_timeout())
            for line in self.lines:
                self.line_count += 1
                for key, value in self.config.items():
                    self.matches = re.finditer(value, line)
                    if self.matches:
                        for match in self.matches:
                                            
                            print(self.render_text("+", Style.BRIGHT + Fore.GREEN, f"possible {key} found : {Style.BRIGHT + Fore.BLUE + match.group() + Style.RESET_ALL} (line {self.line_count})"))
                            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [+] possible {key} found : {Style.BRIGHT + Fore.BLUE + match.group() + Style.RESET_ALL} (line {self.line_count})")
                            self.total_matches += 1
                            self.global_sort(key,match.group())
                            time.sleep(0.2)
            return True
            
        except Exception as e:
        
            print(self.render_text("!",Style.BRIGHT + Fore.RED,f"file check error: {Style.BRIGHT + Fore.WHITE + str(e) + Style.RESET_ALL}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [#] file check error: {e}")
            return False

    def file_info_check(self) -> bool:

        try:
            print()
            print(f"{self.render_text("#",Style.BRIGHT + Fore.BLUE,f"file info check")}")
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [#] file info check")

            if self.ips:
                for ip in self.ips:
                    self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [#] scan ip: {ip}")
                    self.scan_ip(ip)
                    

            if self.domains:
                for domain in self.domains:
                    self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [#] scan domain: {domain}")
                    self.scan_domain(domain)
                    

            if self.urls:
                for url in self.urls:
                    self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [#] scan url: {url}")
                    self.scan_url(url)
                
            
            return True

        except Exception as e:

            print(self.render_text("!",Style.BRIGHT + Fore.RED,f"file info check error: {Style.BRIGHT + Fore.WHITE + str(e) + Style.RESET_ALL}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [!] file info check error: {e}")
            return False

    def file_options_check(self) -> bool:

        try:
            print(f"\n{self.render_text("#",Style.BRIGHT + Fore.BLUE,f"file options check")}")
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [#] file options check")
            self.render_info([f"file size: {ceil(os.path.getsize(Path(self.path)))} bytes",f"md5 hash: {self.hash_file(self.md5_hash)}",f"sha256 hash: {self.hash_file(self.sha256_hash)}",f"sha512 hash: {self.hash_file(self.sha512_hash)}",f"file modification time: {datetime.datetime.fromtimestamp(Path(self.path).stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S.%f')}",f"file creation time: {datetime.datetime.fromtimestamp(Path(self.path).stat().st_ctime).strftime('%Y-%m-%d %H:%M:%S.%f')}"])
            return True

        except Exception as e:
        
            print(self.render_text("!",Style.BRIGHT + Fore.RED,f"file options check error: {Style.BRIGHT + Fore.WHITE + str(e) + Style.RESET_ALL}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [!] file options check error: {e}")
            return False
            
    
    def analyse(self) -> None:

        try:
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] {"-" * 60} START")
            if os.path.isdir(self.path):
                 print(self.render_text("-", Style.BRIGHT + Fore.RED, f"this is not file"))
                 self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [-] {self.path} is not file")
                 return ""

            with open(self.path, "r", encoding="utf-8", errors="ignore") as f:
                self.lines = f.readlines()
                
            print(self.render_text("#", Style.BRIGHT + Fore.BLUE, f"testing file: {Path(self.path)}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [#] testing file: {Path(self.path)}")
            time.sleep(self.get_timeout())


            if not self.skip_file_options_check:
                self.clear_hashes()
                self.file_options_check()
                

            if not self.skip_malware_check:
                if self.virus_total_api_key != "":
                    self.clear_hashes()
                    self.malware_check(self.hash_file(self.sha256_hash))


            if not self.skip_file_check:
                self.clear_hashes()
                self.file_check()


            if not self.skip_file_info_check:

                 if self.virus_total_api_key != "":
                    self.clear_hashes()
                    self.file_info_check()

                    

        except KeyboardInterrupt:

                print(self.render_text("#",Style.BRIGHT + Fore.YELLOW,f"vianto was terminated by user"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [#] vianto was terminated by user")
                time.sleep(self.get_timeout())

        except Exception as e:

                print(self.render_text("!",Style.BRIGHT + Fore.RED,f"error: {Style.BRIGHT + Fore.WHITE + str(e) + Style.RESET_ALL}"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [!] error: {e}")
                time.sleep(self.get_timeout())


        finally:

            if self.client:
                self.client.close()

            if self.total_matches == False:
                print(self.render_text("#",Style.BRIGHT + Fore.RED,f"vianto didn't find any matches in file"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [#] vianto didn't find any matches in file")
                time.sleep(self.get_timeout())


            print(self.render_text("+",Style.BRIGHT + Fore.GREEN,f"vianto completed the analysis in {time.time() - self.timer} seconds"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [+] vianto completed the analysis in {time.time() - self.timer} seconds")
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] {"-" * 60} END")
            time.sleep(self.get_timeout())
            sys.exit(0)

if __name__ == "__main__":

    parser = argparse.ArgumentParser("Vianto (Virus Analyzer Tool) is a fully open-source tool that searches for various data within files using Python regular expressions.")
    parser.add_argument("file_path",type=str,help="File path to check")
    parser.add_argument("-vt","--virus-total",type=str,default="",help="VirusTotal API key for malware check")

    parser.add_argument("-o", "--output-file",nargs="?", const="auto",help="This parameter is responsible for logging all program actions.") 
    parser.add_argument("-t","--timeout",type=float,default=0.0,help="Custom timeout")

    parser.add_argument("-sfoc","--skip-file-options-check",action="store_true",default=False,help="Skip file options check")
    parser.add_argument("-smc","--skip-malware-check",action="store_true",default=False,help="Skip malware check")
    parser.add_argument("-sfc","--skip-file-check",action="store_true",default=False,help="Skip file check")
    parser.add_argument("-sfic","--skip-file-info-check",action="store_true",default=False,help="Skip file info check")

    parser.add_argument("-rt", "--random-timeout", type=str,default=None,help="Random timeout range.for example '--random-timeout '2-5''") 
    parser.add_argument("-j","--jitter", type=float, default=0.0,help="Flag for adding a timeout to the current one. A negative timeout can be specified. Useful in combination with the --random-timeout flag.")

    args = parser.parse_args()
    api_key = args.virus_total

    log_filename = None
        
    if args.output_file == "auto":  
        
        log_filename = f"./logs/{datetime.datetime.now().strftime('%d_%m_%Y_%H_%M_%S')}_logs.txt"
        
    elif args.output_file:  
        
        log_filename = args.output_file

    print(title)
    time.sleep(3)

    try:

        path = sys.argv[1]

    except IndexError:
        path = input("[" + Style.BRIGHT + Fore.BLUE + f"+" + Style.RESET_ALL + "] " + f"you did not specify the path to the desired test file , enter the file path: " + Style.RESET_ALL)
        
    if api_key == "":
         api_key= input("[" + Style.BRIGHT + Fore.BLUE + f"+" + Style.RESET_ALL + "] " + f"before testing begins, provide your VirusTotal API key for additional scanning. You can also specify it using the `--virus-total` flag. If you do not wish to provide an API key, simply press Enter, and the file scanning step will be skipped: " + Style.RESET_ALL)
         

                     
    vianto = Vianto(path,virus_total=api_key,

                    skip_file_options_check = args.skip_file_options_check,
                    skip_malware_check=args.skip_malware_check,
                    skip_file_check=args.skip_file_check,
                    skip_file_info_check=args.skip_file_info_check,
                    timeout=args.timeout,
                    output_file=log_filename,
                    random_timeout=args.random_timeout,
                    jitter=args.jitter)
    vianto.analyse()
