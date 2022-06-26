from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import warnings
from config import username, password
warnings.filterwarnings('ignore')

def main():
    driver = webdriver.PhantomJS(executable_path="/usr/local/share/phantomjs-c2.1.1/bin/phantomjs")

    try:
        driver.get('http://192.168.1.254/')
        print('loading page')

        uname_input = '//*[@id="username"]'
        pass_input = '//*[@id="password"]'
        submit = '//*[@id="loginBT"]'

        WebDriverWait(driver, 60).until(EC.presence_of_element_located((By.XPATH, uname_input)))
        print('login form loaded ',driver.title)
        driver.find_element_by_xpath(uname_input).send_keys(username)
        driver.find_element_by_xpath(pass_input).send_keys(password)
        driver.find_element_by_xpath(submit).click()

        maintenance = '/html/body/div/section/div[1]/div/div[1]/ul[5]'
        reboot = '//*[@id="do_reboot"]'

        WebDriverWait(driver, 30).until(EC.presence_of_element_located((By.XPATH, maintenance)))
        print('login success')
        driver.get('http://192.168.1.254/reboot.cgi')

        WebDriverWait(driver, 30).until(EC.presence_of_element_located((By.XPATH, reboot)))
        print('found reboot button')
        js_confirm = 'window.confirm = function(){return true;}'
        driver.execute_script(js_confirm)
        driver.find_element_by_xpath(reboot).click()
        driver.execute_script('return window.confirm')
        print('reboot done')

    except Exception as e:
        print(e)

    finally:
        driver.quit()

if __name__ == "__main__":
    main()
