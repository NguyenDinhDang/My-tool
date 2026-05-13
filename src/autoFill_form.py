import time
import random
import sys

try:
    import undetected_chromedriver as uc
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
except ImportError:
    print("Vui lòng cài đặt các thư viện cần thiết:")
    print("pip install undetected-chromedriver selenium")
    sys.exit(1)

# Cấu hình data
responses = [
    "Mình muốn thử cà phê lạnh vì thấy mọi người hay uống.",
    "Chắc là cà phê ngọt một chút cho dễ uống.",
    "Mình cũng không rõ, có gì mới thì thử thôi.",
    "Muốn thử cà phê kiểu Hàn Quốc vì nhìn đẹp.",
    "Cà phê nào ít đắng là được.",
    "Mình muốn thử cà phê sữa vì uống quen rồi.",
    "Thật ra không quan trọng lắm, miễn uống được là ok.",
    "Muốn thử loại nào đang hot trên mạng.",
    "Cà phê có vị trái cây nghe cũng lạ nên muốn thử.",
    "Mình thích loại nào dễ uống, không cần đặc biệt.",
    "Có dịp thì thử cà phê đắt tiền xem sao.",
    "Cà phê đá xay chắc ngon nên muốn thử.",
    "Không biết nữa, bạn bè uống gì thì uống theo.",
    "Muốn thử cà phê ít caffeine để đỡ mất ngủ.",
    "Cà phê nào có sữa nhiều chắc hợp hơn.",
    "Thấy mọi người nói cold brew ngon nên muốn thử.",
    "Mình không rành lắm, có gì uống đó thôi.",
    "Muốn thử cà phê vị chocolate cho dễ uống.",
    "Nếu có thì thử loại nào mới mới cho biết.",
    "Không có yêu cầu gì đặc biệt, uống được là được."
]

FORM_URL = "your-form-url-here"  # Thay bằng URL của Google Form bạn muốn điền
NUM_SUBMISSIONS = 27   # Số lượng form bạn muốn điền tự động

def human_type(element, text):
    """Giả lập gõ phím như người thật để tránh bot detection"""
    for char in text:
        element.send_keys(char)
        time.sleep(random.uniform(0.01, 0.08))

def setup_driver():
    options = uc.ChromeOptions()
    options.add_argument('--disable-notifications')
    options.add_argument('--disable-popup-blocking')
    options.add_argument('--start-maximized')
    
    # Khởi tạo undetected_chromedriver giúp qua mặt reCaptcha và Bot Detection của rât nhiều site
    driver = uc.Chrome(options=options, version_main=147)
    return driver

def fill_form(driver):
    wait = WebDriverWait(driver, 15)
    
    # 1. Chọn giới tính (70% Nam/Nữ, 30% Khác)
    # => Xác suất: Nam = 35%, Nữ = 35%, Khác = 30%
    choices = ["Nam", "Nữ", "Không muốn nêu cụ thể"]
    weights = [0.35, 0.35, 0.30]
    gender_choice = random.choices(choices, weights=weights, k=1)[0]
    
    try:
        # Tìm radio có thuộc tính data-value tương ứng cấu trúc Google Form
        radio_locator = f"//div[@data-value='{gender_choice}']"
        radio_element = wait.until(EC.presence_of_element_located((By.XPATH, radio_locator)))
        
        # Scroll để chắc chắn element nằm trong viewport
        driver.execute_script("arguments[0].scrollIntoView({behavior: 'smooth', block: 'center'});", radio_element)
        time.sleep(random.uniform(0.5, 1.0))
        
        # Click thông thường để Google Form chạy đủ event listener (hiệu ứng visual)
        radio_element.click()
    except Exception as e:
        print(f"[-] Bỏ qua bước giới tính do lỗi: {e}")

    # 2. Điền đoạn text trả lời
    answer = random.choice(responses)
    try:
        # Tìm các ô text có thể gõ của form (input ngăn/dài)
        text_inputs = driver.find_elements(By.XPATH, "//input[@type='text'] | //textarea")
        for txt_input in text_inputs:
            driver.execute_script("arguments[0].scrollIntoView({behavior: 'smooth', block: 'center'});", txt_input)
            time.sleep(random.uniform(0.3, 0.8))
            driver.execute_script("arguments[0].focus();", txt_input)
            
            # Gõ chữ từ từ như con người
            human_type(txt_input, answer)
    except Exception as e:
        print(f"[-] Lỗi khi điền text: {e}")

    # 3. Xử lý các câu hỏi checkbox (chọn nhiều đáp án)
    try:
        checkbox_groups = driver.find_elements(By.XPATH, "//div[.//div[@role='checkbox'] and @role='list']")
        
        # Fallback: nếu không nhóm được bằng role='list', tìm tất cả checkbox
        if not checkbox_groups:
            all_checkboxes = driver.find_elements(By.XPATH, "//div[@role='checkbox']")
            if all_checkboxes:
                num_to_tick = max(1, int(len(all_checkboxes) * 0.3))
                to_tick = random.sample(all_checkboxes, min(num_to_tick, len(all_checkboxes)))
                for cb in to_tick:
                    if cb.get_attribute("aria-checked") != "true":
                        driver.execute_script("arguments[0].scrollIntoView({behavior: 'smooth', block: 'center'});", cb)
                        time.sleep(random.uniform(0.3, 0.7))
                        cb.click()
        else:
            for group in checkbox_groups:
                cbs = group.find_elements(By.XPATH, ".//div[@role='checkbox']")
                if cbs:
                    num_to_select = random.randint(1, min(3, len(cbs)))
                    selected_cbs = random.sample(cbs, num_to_select)
                    for cb in selected_cbs:
                        if cb.get_attribute("aria-checked") != "true":
                            driver.execute_script("arguments[0].scrollIntoView({behavior: 'smooth', block: 'center'});", cb)
                            time.sleep(random.uniform(0.3, 0.7))
                            cb.click()
    except Exception as e:
        print(f"[-] Lỗi khi tick checkbox: {e}")

    # 4. Random cho các câu trắc nghiệm khác (Radio Button) nếu form còn nhiều câu
    try:
        radiogroups = driver.find_elements(By.XPATH, "//div[@role='radiogroup']")
        for group in radiogroups:
            checked = group.find_elements(By.XPATH, ".//div[@role='radio' and @aria-checked='true']")
            radios = group.find_elements(By.XPATH, ".//div[@role='radio']")
            if not checked and radios:
                rand_radio = random.choice(radios)
                driver.execute_script("arguments[0].scrollIntoView({behavior: 'smooth', block: 'center'});", rand_radio)
                time.sleep(random.uniform(0.3, 0.7))
                rand_radio.click()
    except Exception:
        pass

    # 5. Click Submit
    try:
        # Tìm nút Gửi (hoặc Submit). Rất dễ bị che nếu dùng scroll/click chuẩn của Selenium
        submit_btn = wait.until(EC.presence_of_element_located(
            (By.XPATH, "//div[@role='button']//span[contains(text(),'G') and contains(text(),'i') and not(contains(text(),'Xóa')) or text()='Submit']/ancestor::div[@role='button'] | //div[@role='button' and .//span[contains(text(),'G') and contains(text(),'i') and not(contains(text(),'Xóa')) or text()='Submit']]")
        ))
        driver.execute_script("arguments[0].scrollIntoView({behavior: 'smooth', block: 'center'});", submit_btn)
        time.sleep(random.uniform(0.5, 1.5))
        
        # Click nút submit
        submit_btn.click()
    except Exception as e:
        print(f"[-] Lỗi click Submit: {e}")
        return False

    # 6. Xử lý "Gửi câu trả lời khác" để lấy form reset
    try:
        another_response = wait.until(EC.element_to_be_clickable((By.PARTIAL_LINK_TEXT, "Gửi câu trả lời khác")))
        time.sleep(random.uniform(1.0, 2.0))
        
        driver.execute_script("arguments[0].scrollIntoView({behavior: 'smooth', block: 'center'});", another_response)
        
        # Click vào link này để Google Form tự tạo session mới
        driver.execute_script("arguments[0].click();", another_response)
        return True
    except Exception as e:
        print(f"[-] Không lấy được link Gửi câu trả lời khác: {e}")
        return False

def main():
    print("Đang khởi tạo Browser...")
    driver = setup_driver()
    driver.get(FORM_URL)
    
    for i in range(NUM_SUBMISSIONS):
        print(f"Đang điền form lần thứ {i + 1}...")
        time.sleep(random.uniform(1.5, 3.0)) # Chờ trang load ổn định
        
        success = fill_form(driver)
        if success:
            print(f"    [OK] Gửi thành công lần {i + 1}")
        else:
            print(f"    [!] Gửi thất bại, tải lại trang để thử lại...")
            driver.get(FORM_URL)
            
        # Thêm biến thời gian ngủ cực kỳ quan trọng để lách Bot Limit của Google Form
        sleep_time = random.uniform(2.5, 5.5)
        print(f"    [Zz] Nghỉ {sleep_time:.2f}s trước khi lặp...\n")
        time.sleep(sleep_time)

    driver.quit()
    print("Đã hoàn thành!")

if __name__ == "__main__":
    main()
