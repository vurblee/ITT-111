import time
from PIL import ImageGrab

counter = 0

while counter <20:   # do 20 times
    time.sleep(20)   # wait 20 seconds
    counter = counter + 1
    #screenshot = pyautogui.screenshot()
    screenshot = ImageGrab.grab()  # Take the screenshot
    screenshot.save("screenshot"+str(counter)+".png")
