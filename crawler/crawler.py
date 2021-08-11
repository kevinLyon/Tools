import sys

import requests
from bs4 import BeautifulSoup


def request(url):

    ## === CUSTOM HEADERS === ##
    header = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"}
    ## === CUSTOM HEADERS === ##

    try:
        response = requests.get(url, headers=header)
        return response.text
    except KeyboardInterrupt:
        sys.exit(0)
    except:
        pass


def get_links(html):
    links = []
    try:
        soup = BeautifulSoup(html, "html.parser")
        tags_a = soup.find_all("a", href=True)
        for tag in tags_a:
            link = tag["href"]
            if link.startswith("http"):
                links.append(link)

        return links
    except:
        pass


def crawl(pre_fix):
    while 1:
        if TO_CRAWL:
            url = TO_CRAWL.pop()

            html = request(url)
            if html:
                links = get_links(html)
                if links:
                    for link in links:
                        if link not in CRAWLED and link not in TO_CRAWL:
                            if pre_fix in link:
                                print(link)
                                TO_CRAWL.append(link)

                CRAWLED.add(url)
            else:
                CRAWLED.add(url)
        else:
            #print("Done")
            break


if __name__ == "__main__":
    #=== LISTS ===
    TO_CRAWL = []
    CRAWLED = set()
    #=== LIST ===

    url = sys.argv[1] #url init
    pre_fix = sys.argv[2] #not scape to scope
    TO_CRAWL.append(url)
    crawl(pre_fix)


    #Saving crawl
    with open("crawler-python.txt", "a") as file:
        for url in CRAWLED:
            file.write(url + "\n")
