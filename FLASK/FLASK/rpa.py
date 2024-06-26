from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException

def send_whatsapp_message(phone, message):
    options = Options()
    # Puedes agregar opciones adicionales según sea necesario
    options.add_argument("--headless")  # Ejecución en modo headless (sin interfaz gráfica)
    
    # Inicializa el driver de Firefox sin especificar 'executable_path'
    driver = webdriver.Firefox(options=options)
    
    try:
        driver.get('https://web.whatsapp.com')
        # Lógica para interactuar con WhatsApp Web
        search_box = WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.XPATH, '//div[@contenteditable="true"][@data-tab="1"]'))
        )
        search_box.send_keys(phone)
        # Puedes agregar más lógica para enviar el mensaje
    except TimeoutException:
        print("Elemento no encontrado. Volviendo a intentar...")
    finally:
        driver.quit()

# Llama a la función para enviar un mensaje
send_whatsapp_message('número_de_teléfono', 'mensaje_a_enviar')