#!/usr/bin/python3
from threading import Thread
import os
import sys

import dns.resolver


# Help menu
def help ():
    os.system("figlet Hunter -f Bloody | lolcat")
    os.system("echo 'Usage: hunter.py < Target > < Wordlist > < Threads > < Verbose [true/false] >' | lolcat")
    os.system("echo 'Example: >> python3 hunter.py google.com wordlist.txt 10' | lolcat")
    os.system("echo 'Example verbose: >> python3 hunter.py google.com wordlist.txt 10 true' | lolcat")
    os.system("echo '\nDefault Threads: 2\nDefault Verbose: false' | lolcat")


# Parsing wordlist
def parser_wordlist(wordlist):
    with open(wordlist, "r") as file:
        words = file.readlines()
        for word in words:
            word = word.strip()
            all_wordlist.append(word)


# Hunting function
def hunter(targett, status_verbose):
    for word in all_wordlist:
        if word in all_wordlist:
            all_wordlist.remove(word)
            if status_verbose == "true":
                print(f"\033[31m[ + ] NOT FOUND: {word}...\033[m")
        try:
            sub_target = f"{word}.{targett}"
            recv = resolver.resolve(sub_target, "A")
            for response in recv:             
                if sub_target not in subdomain_found:
                    print(f"\033[32m[ + ] FOUND: {sub_target}  {response}\033[m")
                    subdomain_found.append(sub_target)
        except:
            pass


# Creating threads
def all_threads(th):
    for thread in range(1, int(th) + 1):
        Thread(target=hunter, args=[target, set_verbose]).start()



if __name__ == "__main__":
    argm = sys.argv
    resolver = dns.resolver.Resolver()
    all_wordlist = [] #Controler for Threads
    subdomain_found = [] #Controler for not duplicate

    # Checking target
    try:
        target = sys.argv[1]
    except:
        help()
        exit()
     
    # Checking wordlist
    try:
        wordlist = sys.argv[2]
        parser_wordlist(wordlist)
    except:
        help()
        exit()
    
    # Checking number of threads
    try:
        number_the_threads = sys.argv[3]
    except:
        number_the_threads = 2

    # Checking Verbose
    try:
        set_verbose = sys.argv[4].lower()
    except:
        set_verbose = "false"

    # Run
    print("\033[35mScanning...\n\033[m")
    all_threads(number_the_threads)
