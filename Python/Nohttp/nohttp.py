import sys

argm = sys.argv
with open(sys.argv[2], "a") as file_to_save:
    with open(sys.argv[1], "r") as file:
        words = file.readlines()
        for word in words:
            word = word.strip()
            if "http://" in word:
                word = word.replace("http://", "")
                file_to_save.write(word + "\n")
            else:
                word = word.replace("https://", "")
                file_to_save.write(word + "\n")
