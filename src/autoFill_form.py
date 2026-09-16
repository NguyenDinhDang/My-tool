import time
import random
import sys
import argparse

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
except ImportError:
    print("Vui lòng cài đặt thư viện cần thiết:")
    print("pip install selenium")
    sys.exit(1)

# Cấu hình data
DEFAULT_RESPONSES = [
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

DEFAULT_NUM_SUBMISSIONS = 1
NUM_SUBMISSIONS = DEFAULT_NUM_SUBMISSIONS

def parse_args():
    parser = argparse.ArgumentParser(
        description="Tu dong dien Google Form voi link va cau tra loi nhap tu CLI."
    )
    parser.add_argument("-u", "--url", help="Link Google Form can dien.")
    parser.add_argument(
        "-a",
        "--answer",
        action="append",
        dest="answers",
        help="Cau tra loi ngan. Co the truyen nhieu lan: -a 'Tra loi 1' -a 'Tra loi 2'.",
    )
    parser.add_argument("-c", "--count", type=int, help="So lan gui form.")
    return parser.parse_args()

def prompt_form_url(current_url=None):
    while not current_url:
        current_url = input("Nhap link Google Form: ").strip()
        if not current_url:
            print("Link khong duoc de trong.")
    return current_url

def prompt_submission_count(current_count=None):
    if current_count is not None:
        if current_count < 1:
            raise ValueError("So lan gui form phai lon hon hoac bang 1.")
        return current_count

    raw_count = input(f"Nhap so lan gui form [{DEFAULT_NUM_SUBMISSIONS}]: ").strip()
    if not raw_count:
        return DEFAULT_NUM_SUBMISSIONS

    count = int(raw_count)
    if count < 1:
        raise ValueError("So lan gui form phai lon hon hoac bang 1.")
    return count

def prompt_answers(current_answers=None):
    answers = [answer.strip() for answer in current_answers or [] if answer.strip()]
    if answers:
        return answers

    print("Nhap cac cau tra loi ngan, moi cau mot dong.")
    print("Bam Enter tren dong trong de ket thuc. Neu bo trong se dung danh sach mac dinh.")
    while True:
        answer = input(f"Cau tra loi {len(answers) + 1}: ").strip()
        if not answer:
            break
        answers.append(answer)

    return answers or DEFAULT_RESPONSES

def type_text(element, text):
    """Điền văn bản vào ô input."""
    element.send_keys(text)

def setup_driver():
    options = Options()
    options.add_argument('--disable-notifications')
    options.add_argument('--disable-popup-blocking')
    options.add_argument('--start-maximized')
    
    driver = webdriver.Chrome(options=options)
    return driver

def fill_form(driver, responses):
    wait = WebDriverWait(driver, 10)
    
    # 1. Chọn giới tính (70% Nam/Nữ, 30% Khác)
    choices = ["Nam", "Nữ", "Không muốn nêu cụ thể"]
    weights = [0.35, 0.35, 0.30]
    gender_choice = random.choices(choices, weights=weights, k=1)[0]
    
    try:
        radio_locator = f"//div[@data-value='{gender_choice}']"
        radio_element = wait.until(EC.element_to_be_clickable((By.XPATH, radio_locator)))
        driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", radio_element)
        radio_element.click()
    except Exception as e:
        print(f"[-] Bỏ qua bước giới tính do lỗi: {e}")

    # 2. Điền đoạn text trả lời
    answer = random.choice(responses)
    try:
        text_inputs = driver.find_elements(By.XPATH, "//input[@type='text'] | //textarea")
        for txt_input in text_inputs:
            driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", txt_input)
            type_text(txt_input, answer)
    except Exception as e:
        print(f"[-] Lỗi khi điền text: {e}")

    # 3. Xử lý các câu hỏi checkbox (chọn nhiều đáp án)
    try:
        checkbox_groups = driver.find_elements(By.XPATH, "//div[.//div[@role='checkbox'] and @role='list']")
        if not checkbox_groups:
            all_checkboxes = driver.find_elements(By.XPATH, "//div[@role='checkbox']")
            if all_checkboxes:
                num_to_tick = max(1, int(len(all_checkboxes) * 0.3))
                to_tick = random.sample(all_checkboxes, min(num_to_tick, len(all_checkboxes)))
                for cb in to_tick:
                    if cb.get_attribute("aria-checked") != "true":
                        driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", cb)
                        cb.click()
        else:
            for group in checkbox_groups:
                cbs = group.find_elements(By.XPATH, ".//div[@role='checkbox']")
                if cbs:
                    num_to_select = random.randint(1, min(3, len(cbs)))
                    selected_cbs = random.sample(cbs, num_to_select)
                    for cb in selected_cbs:
                        if cb.get_attribute("aria-checked") != "true":
                            driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", cb)
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
                driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", rand_radio)
                rand_radio.click()
    except Exception:
        pass

    # 5. Click Submit
    try:
        # Đạo hữu xin nương tay, trận pháp XPath này đang vận hành ổn định để định vị nút Gửi đa ngôn ngữ, chớ dại mà đụng vào kẻo tẩu hỏa nhập ma.
        submit_btn = wait.until(EC.element_to_be_clickable(
            (By.XPATH, "//div[@role='button']//span[contains(text(),'G') and contains(text(),'i') and not(contains(text(),'Xóa')) or text()='Submit']/ancestor::div[@role='button'] | //div[@role='button' and .//span[contains(text(),'G') and contains(text(),'i') and not(contains(text(),'Xóa')) or text()='Submit']]")
        ))
        driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", submit_btn)
        submit_btn.click()
    except Exception as e:
        print(f"[-] Lỗi click Submit: {e}")
        return False

    # 6. Xử lý "Gửi câu trả lời khác" để lấy form reset
    try:
        another_response = wait.until(EC.element_to_be_clickable((By.PARTIAL_LINK_TEXT, "Gửi câu trả lời khác")))
        driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", another_response)
        driver.execute_script("arguments[0].click();", another_response)
        return True
    except Exception as e:
        print(f"[-] Không lấy được link Gửi câu trả lời khác: {e}")
        return False

def run_autofill(url=None, count=None, answers=None):
    try:
        form_url = prompt_form_url(url)
        num_submissions = prompt_submission_count(count if count is not None else NUM_SUBMISSIONS)
        responses = prompt_answers(answers)
    except ValueError as e:
        print(f"Loi cau hinh: {e}")
        sys.exit(1)

    print("Đang khởi tạo Browser...")
    driver = setup_driver()
    try:
        driver.get(form_url)
        
        for i in range(num_submissions):
            print(f"Đang điền form lần thứ {i + 1}...")
            time.sleep(1.0)
            
            success = fill_form(driver, responses)
            if success:
                print(f"    [OK] Gửi thành công lần {i + 1}")
            else:
                print(f"    [!] Gửi thất bại, tải lại trang để thử lại...")
                driver.get(form_url)
                
            time.sleep(1.0)
    finally:
        driver.quit()
        print("Đã hoàn thành!")

def main(url=None, count=None, answers=None):
    if url is None and count is None and answers is None:
        args = parse_args()
        run_autofill(url=args.url, count=args.count, answers=args.answers)
    else:
        run_autofill(url=url, count=count, answers=answers)


if __name__ == "__main__":
    main()
