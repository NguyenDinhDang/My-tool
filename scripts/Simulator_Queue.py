import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import os
import sys

for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, 'reconfigure'):
        stream.reconfigure(encoding='utf-8', errors='replace')

def simulate_queue(lam_min, mu_min, C, dist='M', N=1000, seed=42):
    """
    Mô phỏng hệ thống hàng đợi dựa trên mảng tĩnh.
    lam_min: Tốc độ đến (khách/phút)
    mu_min: Tốc độ phục vụ (khách/phút)
    C: Số lượng quầy phục vụ
    dist: 'M' (Exponential) hoặc 'G' (Gamma)
    """
    np.random.seed(seed)
    
    # 1. Sinh thời gian giữa các lần đến và thời điểm đến
    inter_arrivals = np.random.exponential(1 / lam_min, N)
    arrivals = np.cumsum(inter_arrivals)
    
    # 2. Sinh thời gian phục vụ
    if dist == 'M':
        # Phân phối mũ (Exponential)
        services = np.random.exponential(1 / mu_min, N)
    elif dist == 'G':
        # Phân phối Gamma (shape=4 để giảm phương sai so với mũ, thực tế hơn)
        mean_service = 1 / mu_min
        shape_k = 4
        scale_theta = mean_service / shape_k
        services = np.random.gamma(shape=shape_k, scale=scale_theta, size=N)
    else:
        raise ValueError("Chỉ hỗ trợ phân phối 'M' hoặc 'G'")
        
    # 3. Khởi tạo mảng theo dõi
    starts = np.zeros(N)
    ends = np.zeros(N)
    server_available_times = np.zeros(C)
    
    # 4. Vòng lặp mô phỏng chính (Event processing logic)
    for i in range(N):
        # Tìm quầy trống sớm nhất
        earliest_server_idx = np.argmin(server_available_times)
        
        # Thời điểm bắt đầu phục vụ = max(Thời điểm khách đến, Thời điểm quầy trống)
        starts[i] = max(arrivals[i], server_available_times[earliest_server_idx])
        ends[i] = starts[i] + services[i]
        
        # Cập nhật thời gian bận của quầy
        server_available_times[earliest_server_idx] = ends[i]
        
    # 5. Tính toán các chỉ số
    Wq_array = starts - arrivals  # Thời gian chờ trong hàng đợi
    W_array = ends - arrivals     # Thời gian trong hệ thống
    total_time = np.max(ends)     # Tổng thời gian chạy mô phỏng
    
    lam_eff = N / total_time      # Tốc độ đến hiệu dụng
    
    Wq = np.mean(Wq_array)
    W = np.mean(W_array)
    Lq = lam_eff * Wq             # Định luật Little
    L = lam_eff * W               # Định luật Little
    rho = np.sum(services) / (C * total_time) # Mức sử dụng
    
    return {
        'Số khách': N,
        'Wq (phút)': round(Wq, 2),
        'W (phút)': round(W, 2),
        'Lq (người)': round(Lq, 2),
        'L (người)': round(L, 2),
        'Sử dụng (rho)': round(rho, 3)
    }

def analyze_and_plot(df):
    """Vẽ biểu đồ và in nhận xét tự động"""
    # 1. Vẽ biểu đồ
    fig, axes = plt.subplots(1, 3, figsize=(18, 5))
    metrics = ['Wq (phút)', 'Lq (người)', 'Sử dụng (rho)']
    titles = ['Thời gian chờ trung bình (Wq)', 'Độ dài hàng đợi trung bình (Lq)', 'Mức sử dụng hệ thống (Rho)']
    
    for i, metric in enumerate(metrics):
        df.pivot(index='Mô hình', columns='Bối cảnh', values=metric).plot(
            kind='bar', ax=axes[i], title=titles[i], color=['#1f77b4', '#ff7f0e'], alpha=0.8
        )
        axes[i].set_ylabel(metric)
        axes[i].tick_params(axis='x', rotation=0)
        axes[i].grid(axis='y', linestyle='--', alpha=0.7)
        # Thêm đường giới hạn rho = 1 cho biểu đồ mức sử dụng
        if metric == 'Sử dụng (rho)':
            axes[i].axhline(y=1.0, color='r', linestyle='-', linewidth=2, label='Ngưỡng quá tải (1.0)')
            axes[i].legend()

    plt.tight_layout()
    output_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'output')
    os.makedirs(output_dir, exist_ok=True)
    png_path = os.path.join(output_dir, "queue_comparison.png")
    plt.savefig(png_path)
    plt.show()

    # 2. In nhận xét tự động
    print("\n" + "="*50)
    print("NHẬN XÉT TỰ ĐỘNG TỪ KẾT QUẢ MÔ PHỎNG")
    print("="*50)
    
    for context in df['Bối cảnh'].unique():
        print(f"\n--- Phân tích bối cảnh: {context.upper()} ---")
        sub_df = df[df['Bối cảnh'] == context]
        
        best_model = sub_df.loc[sub_df['Wq (phút)'].idxmin()]
        worst_model = sub_df.loc[sub_df['Wq (phút)'].idxmax()]
        
        print(f"1. Mô hình TỐT NHẤT: {best_model['Mô hình']}")
        print(f"   -> Wq = {best_model['Wq (phút)']} phút, Lq = {best_model['Lq (người)']} người.")
        print(f"   -> Nguyên nhân: Nhiều quầy phục vụ (C>1) kết hợp với thời gian phục vụ ổn định phân phối G (nếu là M/G/C) giúp tối ưu hóa việc phân luồng và giảm rủi ro thắt cổ chai.")
        
        print(f"2. Mô hình ÙN TẮC NHẤT: {worst_model['Mô hình']}")
        print(f"   -> Wq = {worst_model['Wq (phút)']} phút, Lq = {worst_model['Lq (người)']} người, Mức sử dụng (rho) = {worst_model['Sử dụng (rho)']}.")
        
        if worst_model['Sử dụng (rho)'] > 1:
            print(f"   -> NGUYÊN NHÂN NGHIÊM TRỌNG: Hệ số sử dụng rho > 1. Tốc độ khách đến vượt quá năng lực phục vụ của 1 quầy. Hàng đợi tăng tiến tính theo thời gian và không bao giờ giải phóng được.")
        else:
            print(f"   -> Nguyên nhân: Số lượng quầy ít (C=1) và tính ngẫu nhiên cao trong thời gian phục vụ của phân phối mũ (Exponential) gây ra các khoảng nghẽn cục bộ.")

def main():
    # Định nghĩa tham số chung
    N_CUST = 1000
    SEED = 42
    
    # 1. Khai báo kịch bản
    # Chuyển đổi đơn vị sang khách/phút để tránh số thập phân quá nhỏ
    scenarios = [
        {
            'Bối cảnh': 'Siêu thị',
            'lam': 20 / 60,  # 20 khách/giờ
            'mu': 1 / 2,     # Trung bình 2 phút/khách -> 30 khách/giờ -> 0.5 khách/phút
            'C_single': 1, 'C_multi': 4
        },
        {
            'Bối cảnh': 'Ngân hàng',
            'lam': 15 / 60,  # 15 khách/giờ
            'mu': 1 / 5,     # Trung bình 5 phút/khách -> 12 khách/giờ -> 0.2 khách/phút
            'C_single': 1, 'C_multi': 3
        }
    ]
    
    results = []
    
    # 2. Chạy mô phỏng cho từng kịch bản
    for sc in scenarios:
        context = sc['Bối cảnh']
        lam = sc['lam']
        mu = sc['mu']
        
        # M/M/1
        res = simulate_queue(lam, mu, C=sc['C_single'], dist='M', N=N_CUST, seed=SEED)
        res.update({'Bối cảnh': context, 'Mô hình': 'M/M/1'})
        results.append(res)
        
        # M/M/C
        res = simulate_queue(lam, mu, C=sc['C_multi'], dist='M', N=N_CUST, seed=SEED)
        res.update({'Bối cảnh': context, f"Mô hình": f"M/M/{sc['C_multi']}"})
        results.append(res)
        
        # M/G/1
        res = simulate_queue(lam, mu, C=sc['C_single'], dist='G', N=N_CUST, seed=SEED)
        res.update({'Bối cảnh': context, 'Mô hình': 'M/G/1'})
        results.append(res)
        
        # M/G/C
        res = simulate_queue(lam, mu, C=sc['C_multi'], dist='G', N=N_CUST, seed=SEED)
        res.update({'Bối cảnh': context, 'Mô hình': f"M/G/{sc['C_multi']}"})
        results.append(res)

    # 3. Định dạng và xuất dữ liệu
    df = pd.DataFrame(results)
    # Sắp xếp lại cột cho đẹp
    cols = ['Bối cảnh', 'Mô hình', 'Số khách', 'Wq (phút)', 'W (phút)', 'Lq (người)', 'L (người)', 'Sử dụng (rho)']
    df = df[cols]
    
    print("BẢNG KẾT QUẢ MÔ PHỎNG:")
    print(df.to_string(index=False))
    
    output_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'output')
    os.makedirs(output_dir, exist_ok=True)
    csv_filename = os.path.join(output_dir, 'ket_qua_mo_phong_hang_doi.csv')
    df.to_csv(csv_filename, index=False, encoding='utf-8-sig')
    print(f"\nĐã xuất kết quả ra file: {os.path.abspath(csv_filename)}")
    
    # 4. Trực quan hóa và đánh giá
    analyze_and_plot(df)


if __name__ == "__main__":
    main()