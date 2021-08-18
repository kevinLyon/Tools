import re
import json
import argparse
from threading import Thread

import requests



parser = argparse.ArgumentParser(description="JS-scan")
parser.add_argument("-v", "--verbose", metavar="", default="0", help="Set method verbose [ Default: 0 ]") #mudar para zero
parser.add_argument("-t", "--threads", metavar="", default="2", help="Set number of threads [ Default: 2 ]")
parser.add_argument("-f", "--file", metavar="", help="Set file who url's")
parser.add_argument("-r", "--regex", metavar="", default="regex.json", help="Set you file regex [ Default: regex.json]")
arguments = parser.parse_args()

def list_regex(file):
    try:
        with open(file, "r") as file:
            regexs = json.load(file)
            return regexs
    except Exception as error:
        print(f"\n\n\033[31mError {error}\033[m\n\n")




def list_urls(file):
    try:
        with open(file, "r") as file:
            urls = file.readlines()
            for url in urls:
                url = url.strip()
                all_urls.append(url)
    except Exception as error:
        print(f"\n\n\033[31mError {error}\033[m\n\n")


def analizer(verbose, all_regex):
    while len(all_urls) > 0:
        url = all_urls[0]
        all_urls.remove(url)
        try:
            get = requests.get(url)
            doc = get.text
            if doc:
                for regexs in all_regex:
                    matches = re.findall(rf"{regexs['regex']}", doc, re.MULTILINE)
                    if matches:
                        if verbose == "1":
                            print(f"\033[35m {regexs['nome']} \033[m")
                            print(f"\033[32m {get.url} \033[m")
                        elif verbose == "2":
                            print(f"\033[35m{get.url}\033[m")
                            for data in matches:
                                print(f"\033[35m[ + ] FOUND: {data}\033[m")

        except Exception as error:
            print(regexs)
            print("\033[31m\nError in def analizer\033[m")
            print(f"\033[31mError {error}\033[m\n\n")


        #enable here to debug
        #break


def all_threads(verbose, all_regex):
    controler = 0
    for thread in range(0 + int(number_threads)):
        Thread(target=analizer, args=[verbose, all_regex]).start()
        controler += 1



if __name__ == "__main__":
    ## === args === ##
    number_threads = arguments.threads
    method_verbose = arguments.verbose
    set_file = arguments.file
    set_list_regex = arguments.regex
    ## === args === ##

    ## === lists === ##
    all_urls = []
    ## === list === ##

    list_urls(set_file)
    list_all_regex = list_regex(set_list_regex)

    # RUN
    if all_urls:
        all_threads(method_verbose, list_all_regex)
    else:
        print("\n\033[31m No found urls \033[m")
