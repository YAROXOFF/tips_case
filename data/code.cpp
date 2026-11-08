#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstdlib>
#include <ctime>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <iomanip>

using namespace std;

// === Исходные файлы ===
const string QR_FILE           = "qr_links.csv";
const string PAYMENTS_FILE     = "payments.csv";
const string QR_GEN_FILE       = "qr_links_generated.csv";
const string PAYMENTS_OUT_FILE = "payments_out.csv";
const string SECRET_KEY        = "demo-secret-k3";

// === Ограничения ===
const double BASE_AMOUNT      = 1000.0;      // fallback для старых QR без UNPAID
const double MAX_CHECK_AMOUNT = 1000000.0;   // верхняя граница чека при создании QR
const double MAX_TOTAL_AMOUNT = 1200000.0;   // P-3: верхняя граница суммы с чаевыми

// =====================================================================
// РЕАЛИЗАЦИЯ SHA-256 И HMAC (нужно для проверки подписи QR - Q-1)
// =====================================================================
namespace SHA256 {
    uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

    void transform(uint32_t state[8], const uint8_t block[64]) {
        uint32_t w[64];
        const uint32_t K[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };
        
        for (int i = 0; i < 16; ++i)
            w[i] = ((uint32_t)block[i*4] << 24) | ((uint32_t)block[i*4+1] << 16) | ((uint32_t)block[i*4+2] << 8) | ((uint32_t)block[i*4+3]);
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3);
            uint32_t s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        
        uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t temp1 = h + S1 + ch + K[i] + w[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;
            h = g; g = f; f = e; e = d + temp1;
            d = c; c = b; b = a; a = temp1 + temp2;
        }
        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }

    void hash_raw(const string& input, uint8_t out[32]) {
        uint32_t state[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
        uint64_t bit_len = input.length() * 8;
        
        string msg = input;
        msg += (char)0x80;
        while (msg.length() % 64 != 56) msg += (char)0x00;
        for (int i = 7; i >= 0; --i) msg += (char)((bit_len >> (i * 8)) & 0xFF);

        for (size_t i = 0; i < msg.length(); i += 64) {
            transform(state, (const uint8_t*)&msg[i]);
        }

        for (int i = 0; i < 8; ++i) {
            out[i*4]   = (state[i] >> 24) & 0xFF;
            out[i*4+1] = (state[i] >> 16) & 0xFF;
            out[i*4+2] = (state[i] >> 8) & 0xFF;
            out[i*4+3] = state[i] & 0xFF;
        }
    }

    string hmac_sha256(const string& key, const string& msg) {
        uint8_t o_key_pad[64], i_key_pad[64];
        memset(o_key_pad, 0x5c, 64);
        memset(i_key_pad, 0x36, 64);
        
        for (size_t i = 0; i < key.length() && i < 64; ++i) {
            o_key_pad[i] ^= key[i];
            i_key_pad[i] ^= key[i];
        }
        
        string inner_in = string((char*)i_key_pad, 64) + msg;
        uint8_t inner_hash[32];
        hash_raw(inner_in, inner_hash);
        
        string outer_in = string((char*)o_key_pad, 64) + string((char*)inner_hash, 32);
        uint8_t outer_hash[32];
        hash_raw(outer_in, outer_hash);
        
        stringstream ss;
        for (int i = 0; i < 32; ++i) {
            ss << hex << setw(2) << setfill('0') << (int)outer_hash[i];
        }
        return ss.str();
    }
}

// === Вспомогательные функции (ВОЗВРАЩЕНЫ!) ===
vector<string> split(const string& line) {
    vector<string> result;
    stringstream ss(line);
    string item;
    while (getline(ss, item, ',')) result.push_back(item);
    return result;
}

string money(double v) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%.2f", v);
    return string(buf);
}

// Формат денег для CSV (точка вместо запятой)
string money_csv(double v) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%.2f", v);
    string s(buf);
    for (auto& c : s) if (c == ',') c = '.';
    return s;
}

bool file_empty_or_missing(string filename) {
    ifstream f(filename);
    if (!f.is_open()) return true;
    f.seekg(0, ios::end);
    bool empty = (f.tellg() == 0);
    f.close();
    return empty;
}

string generate_hex(int len) {
    string hex = "0123456789abcdef";
    string res = "";
    for (int i = 0; i < len; i++) res += hex[rand() % 16];
    return res;
}

// Обновляет запись платежа по payment_id. Если нет — добавляет.
bool update_or_append_payment(const string& payment_id,
                              const string& m_id, const string& e_id,
                              double amount, double tip,
                              const string& status, const string& timestamp) {
    ifstream in(PAYMENTS_OUT_FILE);
    if (in.is_open()) {
        vector<string> lines;
        string line;
        bool found = false;
        while (getline(in, line)) {
            vector<string> parts = split(line);
            if (parts.size() >= 1 && parts[0] == payment_id) {
                stringstream ss;
                ss << payment_id << "," << m_id << "," << e_id << ","
                   << money_csv(amount) << "," << money_csv(tip) << ","
                   << status << "," << timestamp;
                line = ss.str();
                found = true;
            }
            lines.push_back(line);
        }
        in.close();
        if (found) {
            ofstream out(PAYMENTS_OUT_FILE);
            if (!out.is_open()) return false;
            for (auto& l : lines) out << l << "\n";
            out.close();
            return true;
        }
    }
    
    bool need_header = file_empty_or_missing(PAYMENTS_OUT_FILE);
    ofstream out(PAYMENTS_OUT_FILE, ios::app);
    if (!out.is_open()) return false;
    if (need_header)
        out << "payment_id,merchant_id,employee_id,amount,tip,status,timestamp" << endl;
    out << payment_id << "," << m_id << "," << e_id << ","
        << money_csv(amount) << "," << money_csv(tip) << ","
        << status << "," << timestamp << endl;
    out.close();
    return true;
}

// === Поиск по файлам ===
bool find_merchant(string m_id, string& name, string& status) {
    ifstream f("merchants.csv");
    string line;
    getline(f, line);
    while (getline(f, line)) {
        vector<string> parts = split(line);
        if (parts.size() >= 3 && parts[0] == m_id) {
            name = parts[1]; status = parts[2];
            return true;
        }
    }
    return false;
}

bool find_officer(string e_id, string& m_id, string& name, string& details) {
    ifstream f("employees.csv");
    string line;
    getline(f, line);
    while (getline(f, line)) {
        vector<string> parts = split(line);
        if (parts.size() >= 4 && parts[0] == e_id) {
            m_id = parts[1]; name = parts[2]; details = parts[3];
            return true;
        }
    }
    return false;
}

string get_merchant_status(string m_id) {
    string name, status;
    if (find_merchant(m_id, name, status)) return status;
    return "";
}

bool find_qr_in_file(string filename, string target, string& m_id, string& e_id,
                     string& r_id, string& nonce, string& exp, string& sig) {
    ifstream f(filename);
    if (!f.is_open()) return false;
    string line;
    getline(f, line);
    while (getline(f, line)) {
        vector<string> parts = split(line);
        if (parts.size() >= 7 && parts[0] == target) {
            m_id = parts[1]; e_id = parts[2]; r_id = parts[3];
            nonce = parts[4]; exp = parts[5]; sig = parts[6];
            f.close();
            return true;
        }
    }
    f.close();
    return false;
}

bool find_qr(string target, string& m_id, string& e_id, string& r_id,
             string& nonce, string& exp, string& sig) {
    if (find_qr_in_file(QR_FILE, target, m_id, e_id, r_id, nonce, exp, sig)) return true;
    if (find_qr_in_file(QR_GEN_FILE, target, m_id, e_id, r_id, nonce, exp, sig)) return true;
    return false;
}

// === Генерация QR ===
int find_max_qr_number() {
    int max_num = 0;
    string files[] = {QR_FILE, QR_GEN_FILE};
    for (int fi = 0; fi < 2; fi++) {
        ifstream f(files[fi]);
        if (!f.is_open()) continue;
        string line;
        getline(f, line);
        while (getline(f, line)) {
            vector<string> parts = split(line);
            if (parts.size() >= 1 && parts[0].length() > 3) {
                int num = atoi(parts[0].substr(3).c_str());
                if (num > max_num) max_num = num;
            }
        }
        f.close();
    }
    return max_num;
}

string format_qr_id(int n) {
    string s = to_string(n);
    while (s.length() < 3) s = "0" + s;
    return "qr_" + s;
}

bool receipt_exists(string m_id, string r_id) {
    string files[] = {QR_FILE, QR_GEN_FILE};
    for (int fi = 0; fi < 2; fi++) {
        ifstream f(files[fi]);
        if (!f.is_open()) continue;
        string line;
        getline(f, line);
        while (getline(f, line)) {
            vector<string> parts = split(line);
            if (parts.size() >= 4 && parts[1] == m_id && parts[3] == r_id) {
                f.close();
                return true;
            }
        }
        f.close();
    }
    return false;
}

void generate_qr(string m_id, string e_id) {
    string status = get_merchant_status(m_id);
    if (status != "ACTIVE") {
        cout << "Ошибка: мерчант в статусе " << status
             << " — QR не создаётся (MERCHANT_BLOCKED)" << endl;
        return;
    }
    string r_id;
    cout << "Введите номер чека (например, r_2001): ";
    cin >> r_id;

    if (receipt_exists(m_id, r_id)) {
        cout << "Ошибка: для чека " << r_id << " уже есть QR." << endl;
        return;
    }

    double base_amount = 0.0;
    while (true) {
        cout << "Введите сумму чека в рублях (например, 1500 или 1500.50): ";
        string amt_str;
        cin >> amt_str;
        for (auto& ch : amt_str) if (ch == ',') ch = '.'; 
        char* endp = nullptr;
        base_amount = strtod(amt_str.c_str(), &endp);
        if (endp == amt_str.c_str() || *endp != '\0' || base_amount <= 0.0 || base_amount > MAX_CHECK_AMOUNT) {
            cout << "Ошибка: введите число от 0.01 до " << money(MAX_CHECK_AMOUNT) << " руб." << endl;
            continue;
        }
        break;
    }

    int next_num = find_max_qr_number() + 1;
    string qr_id = format_qr_id(next_num);
    string nonce = generate_hex(6);
    string exp   = "2025-12-31T23:59:00Z";

    string payload = m_id + "|" + e_id + "|" + r_id + "|" + nonce + "|" + exp;
    string full_hash = SHA256::hmac_sha256(SECRET_KEY, payload);
    string sig = full_hash.substr(0, 16);

    bool need_header = file_empty_or_missing(QR_GEN_FILE);
    ofstream f(QR_GEN_FILE, ios::app);
    if (!f.is_open()) {
        cout << "Ошибка записи в " << QR_GEN_FILE << endl;
        return;
    }
    if (need_header)
        f << "qr_id,merchant_id,employee_id,receipt_id,nonce,exp,signature" << endl;
    f << qr_id << "," << m_id << "," << e_id << "," << r_id << ","
      << nonce << "," << exp << "," << sig << endl;
    f.close();

    // Отправляем QR в файл оплаты со статусом UNPAID
    string payment_id = "p_" + qr_id.substr(3);
    bool unpaid_ok = update_or_append_payment(payment_id, m_id, e_id, base_amount, 0.0, "UNPAID", "0000-00-00T00:00:00Z");

    cout << "\n=== QR УСПЕШНО СОЗДАН (записан в " << QR_GEN_FILE << ") ===" << endl;
    cout << "ID:        " << qr_id << endl;
    cout << "Мерчант:   " << m_id << endl;
    cout << "Официант:  " << e_id << endl;
    cout << "Чек:       " << r_id << endl;
    cout << "Сумма:     " << money(base_amount) << " руб." << endl;
    cout << "Истекает:  " << exp << endl;
    if (unpaid_ok) {
        cout << "Платёж " << payment_id << " создан со статусом UNPAID в " << PAYMENTS_OUT_FILE << endl;
    } else {
        cout << "Предупреждение: не удалось создать запись UNPAID в " << PAYMENTS_OUT_FILE << endl;
    }
    cout << "Сообщите клиенту ID: " << qr_id << endl;
}

// === Отчёты ===
void show_merchant_report(string m_id) {
    double tips_total = 0;
    int payments_count = 0, success_count = 0, pct_count = 0;
    double pct_sum = 0;
    string files[] = {PAYMENTS_FILE, PAYMENTS_OUT_FILE};
    for (int fi = 0; fi < 2; fi++) {
        ifstream f(files[fi]);
        if (!f.is_open()) continue;
        string line;
        getline(f, line);
        while (getline(f, line)) {
            vector<string> parts = split(line);
            if (parts.size() < 6 || parts[1] != m_id) continue;
            if (parts[5] == "UNPAID") continue;
            payments_count++;
            if (parts[5] == "SUCCESS") {
                double tip = atof(parts[4].c_str()), amount = atof(parts[3].c_str());
                tips_total += tip; success_count++;
                if (amount > 0) { pct_sum += (tip / amount) * 100.0; pct_count++; }
            }
        }
        f.close();
    }
    double avg_pct = pct_count > 0 ? pct_sum / pct_count : 0;
    double success_rate = payments_count > 0 ? (double)success_count / payments_count : 0;
    cout << "\n=== ОТЧЁТ ПО ЗАВЕДЕНИЮ " << m_id << " ===" << endl;
    cout << "Всего платежей:          " << payments_count << endl;
    cout << "Успешных:                " << success_count << endl;
    cout << "Сумма чаевых (SUCCESS):  " << money(tips_total) << " руб." << endl;
    cout << "Средний процент чаевых:  " << money(avg_pct) << "%" << endl;
    cout << "Доля успешных:           " << money(success_rate) << endl;
}

void show_merchant_officers(string m_id) {
    cout << "\n=== ОФИЦИАНТЫ ЗАВЕДЕНИЯ " << m_id << " ===" << endl;
    ifstream f("employees.csv");
    string line;
    getline(f, line);
    int count = 0;
    while (getline(f, line)) {
        vector<string> parts = split(line);
        if (parts.size() >= 4 && parts[1] == m_id) {
            cout << parts[0] << " | " << parts[2] << " | реквизиты: " << parts[3] << endl;
            count++;
        }
    }
    if (count == 0) cout << "(нет официантов)" << endl;
}

void show_officer_tips(string e_id) {
    double tips_total = 0;
    int success_count = 0, total_count = 0;
    string files[] = {PAYMENTS_FILE, PAYMENTS_OUT_FILE};
    for (int fi = 0; fi < 2; fi++) {
        ifstream f(files[fi]);
        if (!f.is_open()) continue;
        string line;
        getline(f, line);
        while (getline(f, line)) {
            vector<string> parts = split(line);
            if (parts.size() < 6 || parts[2] != e_id) continue;
            if (parts[5] == "UNPAID") continue;
            total_count++;
            if (parts[5] == "SUCCESS") {
                tips_total += atof(parts[4].c_str()); success_count++;
            }
        }
        f.close();
    }
    double avg = success_count > 0 ? tips_total / success_count : 0;
    cout << "\n=== ВАШИ ЧАЕВЫЕ (" << e_id << ") ===" << endl;
    cout << "Успешных платежей:        " << success_count << " из " << total_count << endl;
    cout << "Сумма чаевых:             " << money(tips_total) << " руб." << endl;
    cout << "Средние чаевые за платёж: " << money(avg) << " руб." << endl;
}

// === Сессии ===
void merchant_session(string m_id, string m_name, string m_status) {
    if (m_status != "ACTIVE") {
        cout << "\nВаш мерчант в статусе " << m_status << ". (MERCHANT_BLOCKED)" << endl;
        return;
    }
    while (true) {
        cout << "\n--- МЕНЮ МЕРЧАНТА: " << m_name << " (" << m_id << ") ---" << endl;
        cout << "1. Отчёт по заведению\n2. Список официантов\n3. Сгенерировать QR на чек\n0. Выйти\nВыбор: ";
        int c; cin >> c;
        if (c == 1) show_merchant_report(m_id);
        else if (c == 2) show_merchant_officers(m_id);
        else if (c == 3) {
            string e_id;
            cout << "Введите ID официанта (например, e_001): ";
            cin >> e_id;
            string em_id, ename, edet;
            if (!find_officer(e_id, em_id, ename, edet)) cout << "Ошибка: официант не найден." << endl;
            else if (em_id != m_id) cout << "Ошибка: этот официант не работает в вашем заведении." << endl;
            else generate_qr(m_id, e_id);
        }
        else if (c == 0) break;
    }
}

void officer_session(string e_id, string e_name, string e_m_id) {
    string m_status = get_merchant_status(e_m_id);
    if (m_status != "ACTIVE") {
        cout << "\nМерчант " << e_m_id << " в статусе " << m_status << " — QR недоступен." << endl;
        return;
    }
    while (true) {
        cout << "\n--- МЕНЮ ОФИЦИАНТА: " << e_name << " (" << e_id << ") ---" << endl;
        cout << "1. Сгенерировать QR на чек\n2. Мои чаевые\n0. Выйти\nВыбор: ";
        int c; cin >> c;
        if (c == 1) generate_qr(e_m_id, e_id);
        else if (c == 2) show_officer_tips(e_id);
        else if (c == 0) break;
    }
}

// === Оплата (Клиент) ===
void client_pay() {
    cout << "\n--- ОПЛАТА ЧАЕВЫХ (КЛИЕНТ) ---" << endl;
    cout << "Введите ID QR-кода с чека (например, qr_001): ";
    string target; cin >> target;

    string m_id, e_id, r_id, nonce, exp, sig;
    if (!find_qr(target, m_id, e_id, r_id, nonce, exp, sig)) {
        cout << "Ошибка: QR не найден (INVALID_QR)" << endl;
        return;
    }

    string now = "2025-11-01T12:00:00Z";
    if (exp < now) {
        cout << "Ошибка: QR истёк (QR_EXPIRED)" << endl;
        return;
    }

    string payload = m_id + "|" + e_id + "|" + r_id + "|" + nonce + "|" + exp;
    string full_hash = SHA256::hmac_sha256(SECRET_KEY, payload);
    string expected_sig = full_hash.substr(0, 16);
    if (expected_sig != sig) {
        cout << "Ошибка: Неверная подпись QR! (INVALID_QR)" << endl;
        return;
    }
    cout << "[OK] Подпись QR проверена (HMAC-SHA256)." << endl;

    string payment_id = "p_" + target.substr(3);
    bool already_paid  = false;
    bool found_unpaid  = false;
    double stored_amount = 0.0;

    ifstream check_out(PAYMENTS_OUT_FILE);
    if (check_out.is_open()) {
        string line;
        getline(check_out, line);
        while (getline(check_out, line)) {
            vector<string> parts = split(line);
            if (parts.size() >= 6 && parts[0] == payment_id) {
                if (parts[5] != "UNPAID") {
                    already_paid = true;
                } else {
                    found_unpaid  = true;
                    stored_amount = atof(parts[3].c_str());
                }
            }
        }
        check_out.close();
    }

    if (already_paid) {
        cout << "\n[P-2] Платёж по этому QR уже был обработан ранее!" << endl;
        cout << "Возврат существующего платежа. Новый не создаём." << endl;
        return;
    }

    double base_amount = found_unpaid ? stored_amount : BASE_AMOUNT;

    string m_status = get_merchant_status(m_id);
    if (m_status != "ACTIVE") {
        cout << "Ошибка: заведение недоступно (MERCHANT_BLOCKED, " << m_status << ")" << endl;
        return;
    }

    cout << "\nЗаведение: " << m_id << " (официант " << e_id << ")" << endl;
    cout << "Чек: " << money(base_amount) << " руб." << endl;
    cout << "\nВыберите чаевые:\n1. 5%\n2. 10%\n3. 20%\n4. Своя сумма\n5. Без чаевых\nВыбор: ";
    int c; cin >> c;
    double tip_pct = 0;
    if      (c == 1) tip_pct = 5;
    else if (c == 2) tip_pct = 10;
    else if (c == 3) tip_pct = 20;
    else if (c == 5) tip_pct = 0;
    else if (c == 4) {
        cout << "Введите процент (0-50): "; cin >> tip_pct;
        if (tip_pct < 0 || tip_pct > 50) { cout << "Ошибка: TIP_OUT_OF_RANGE" << endl; return; }
    } else { cout << "Неверный выбор" << endl; return; }

    double tip = base_amount * tip_pct / 100.0;
    double total = base_amount + tip;

    if (total > MAX_TOTAL_AMOUNT) {
        cout << "Ошибка: AMOUNT_OUT_OF_RANGE" << endl;
        return;
    }

    int qr_num = atoi(target.substr(3).c_str());
    int h = qr_num % 10;
    string status;
    if (h <= 6)      { status = "SUCCESS";  cout << "\n[Эмулятор] SUCCESS: Оплата прошла успешно." << endl; }
    else if (h == 7) { status = "DECLINED"; cout << "\n[Эмулятор] DECLINED: банк отклонил." << endl; }
    else if (h == 8) { status = "PENDING";  cout << "\n[Эмулятор] PENDING (timeout)." << endl; }
    else             { status = "CANCELED"; cout << "\n[Эмулятор] CANCELED." << endl; }

    if (update_or_append_payment(payment_id, m_id, e_id, base_amount, tip, status, "2025-11-01T18:00:00Z")) {
        cout << "Платёж " << payment_id << " обновлён: " << status << " (файл " << PAYMENTS_OUT_FILE << ")" << endl;
    } else {
        cout << "Ошибка: не удалось обновить/сохранить платёж." << endl;
    }
}

// === Вход ===
void login_merchant() {
    string m_id;
    cout << "Введите merchant_id (например, m_001): "; cin >> m_id;
    string name, status;
    if (!find_merchant(m_id, name, status)) { cout << "Мерчант не найден." << endl; return; }
    cout << "\nВход выполнен: " << name << " (статус: " << status << ")" << endl;
    merchant_session(m_id, name, status);
}

void login_officer() {
    string e_id;
    cout << "Введите employee_id (например, e_001): "; cin >> e_id;
    string m_id, name, details;
    if (!find_officer(e_id, m_id, name, details)) { cout << "Официант не найден." << endl; return; }
    cout << "\nВход выполнен: " << name << " (мерчант: " << m_id << ")" << endl;
    officer_session(e_id, name, m_id);
}

// === main ===
int main() {
    system("chcp 1251 > nul"); 
    setlocale(LC_ALL, "ru_RU.UTF-8");
    srand(time(0));

    while (true) {
        cout << "\n======================================" << endl;
        cout << "  ПЛАТФОРМА ДЛЯ ОПЛАТЫ 'ВКУС-СЕРВИС'" << endl;
        cout << "======================================" << endl;
        cout << "1. Вход мерчанта\n2. Вход официанта\n3. Оплатить (клиент)\n0. Выход\nВыберите: ";
        int c; cin >> c;
        if      (c == 1) login_merchant();
        else if (c == 2) login_officer();
        else if (c == 3) client_pay();
        else if (c == 0) break;
        else cout << "Неверный пункт." << endl;
    }
    return 0;
}