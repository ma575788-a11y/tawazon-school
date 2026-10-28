import streamlit as st
import sqlite3
import pandas as pd
import hashlib
import hmac
import secrets
from datetime import date, timedelta
from pathlib import Path
from io import BytesIO
import re
import os
import json
import base64
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone, timedelta as time_delta

st.set_page_config(page_title='توازن', page_icon='📚', layout='wide', initial_sidebar_state='collapsed')
DB = Path(__file__).with_name('tawazon_teacher_demo.db')
DEMO_MODE = True
DAYS = ['الأحد', 'الاثنين', 'الثلاثاء', 'الأربعاء', 'الخميس']
PERIODS = list(range(1, 8))

CLASS_LABELS = {str(101 + i): f'{["أول", "ثاني", "ثالث"][i // 5]} ثانوي {i % 5 + 1}' for i in range(15)}
SCHOOL_CLASSES = list(CLASS_LABELS)

def canonical_class(value):
    raw = str(value or '').strip()
    if raw in CLASS_LABELS:
        return raw
    for key, label in CLASS_LABELS.items():
        grade = (int(key) - 101) // 5 + 1
        section = (int(key) - 101) % 5 + 1
        aliases = {label, label.replace(' ثانوي ', ' ثانوي - '), f'{grade}/{section}', f'{grade}-{section}', f'{grade}\\{section}'}
        if raw in aliases:
            return key
    return raw

def class_label(value):
    return CLASS_LABELS.get(canonical_class(value), str(value or ''))

def normalize_school_classes():
    with connect() as conn:
        tables = ('users', 'teacher_classes', 'timetable', 'tasks')
        changes = {}
        for table in tables:
            values = [row[0] for row in conn.execute(f'SELECT DISTINCT class_name FROM {table}')]
            changes[table] = [(old, canonical_class(old)) for old in values if old and canonical_class(old) != old]
        if not any(changes.values()):
            return None
        conflicts = []
        for table, cols in (('timetable', ('day', 'period')), ('teacher_classes', ('teacher_id',))):
            seen = set()
            for row in conn.execute(f'SELECT class_name,{",".join(cols)} FROM {table}'):
                key = (canonical_class(row[0]), *tuple(row[1:]))
                if key in seen:
                    conflicts.append(f'{table}: {key[0]}')
                seen.add(key)
        if conflicts:
            return 'تعذر توحيد أسماء بعض الفصول بسبب وجود سجلات متعارضة. لم يتم تغيير أي بيانات. يلزم مراجعة قاعدة البيانات: ' + '، '.join(sorted(set(conflicts))[:5])
        backup = DB.with_name('tawazon_backup_before_class_fix.db')
        if not backup.exists():
            with sqlite3.connect(backup) as destination:
                conn.backup(destination)
        for table, replacements in changes.items():
            for old, new in replacements:
                conn.execute(f'UPDATE {table} SET class_name=? WHERE class_name=?', (new, old))
    return None

def connect():
    c = sqlite3.connect(DB, timeout=15)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON')
    return c

def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 250000).hex()
    return f'{salt}${digest}'

def check_password(password, saved):
    try:
        salt, _ = saved.split('$', 1)
        return hmac.compare_digest(password_hash(password, salt), saved)
    except (ValueError, TypeError):
        return False

def init():
    with connect() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','teacher','student')),
            class_name TEXT NOT NULL DEFAULT '',
            active INTEGER NOT NULL DEFAULT 1,
            must_change_password INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS teacher_classes (
            teacher_id INTEGER NOT NULL,
            class_name TEXT NOT NULL,
            PRIMARY KEY (teacher_id, class_name),
            FOREIGN KEY (teacher_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS timetable (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            class_name TEXT NOT NULL,
            day TEXT NOT NULL,
            period INTEGER NOT NULL CHECK(period BETWEEN 1 AND 7),
            subject TEXT NOT NULL,
            teacher_id INTEGER NOT NULL,
            UNIQUE(class_name, day, period),
            UNIQUE(teacher_id, day, period),
            FOREIGN KEY (teacher_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            subject TEXT NOT NULL,
            class_name TEXT NOT NULL,
            kind TEXT NOT NULL CHECK(kind IN ('واجب','اختبار')),
            due_date TEXT NOT NULL,
            teacher_id INTEGER NOT NULL,
            details TEXT NOT NULL DEFAULT '',
            FOREIGN KEY (teacher_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS completions (
            student_id INTEGER NOT NULL,
            task_id INTEGER NOT NULL,
            PRIMARY KEY(student_id, task_id),
            FOREIGN KEY(student_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
        );
        ''')
        cols = {r[1] for r in c.execute('PRAGMA table_info(users)')}
        if 'must_change_password' not in cols:
            c.execute('ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0')
        if 'phone' not in cols:
            c.execute("ALTER TABLE users ADD COLUMN phone TEXT NOT NULL DEFAULT ''")
        c.execute('''CREATE TABLE IF NOT EXISTS sms_verifications (
            user_id INTEGER PRIMARY KEY,
            code_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            sent_at TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS activation_codes (
            user_id INTEGER PRIMARY KEY,
            code_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )''')

def fetch(sql, args=()):
    with connect() as c:
        return [dict(x) for x in c.execute(sql, args).fetchall()]

def execute(sql, args=()):
    with connect() as c:
        return c.execute(sql, args).rowcount

def create_user(username, full_name, password, role, class_name='', temporary=False):
    with connect() as c:
        c.execute('INSERT INTO users(username,full_name,password_hash,role,class_name,must_change_password) VALUES(?,?,?,?,?,?)',
                  (username.strip(), full_name.strip(), password_hash(password), role, class_name.strip(), int(temporary)))

def classes():
    return SCHOOL_CLASSES.copy()

def allowed_classes(user):
    if user['role'] == 'admin':
        return classes()
    if user['role'] == 'student':
        return [user['class_name']] if user['class_name'] else []
    return [x['class_name'] for x in fetch('SELECT class_name FROM teacher_classes WHERE teacher_id=? ORDER BY class_name', (user['id'],))]

def activation_code_hash(code):
    return hashlib.sha256(code.strip().upper().encode('utf-8')).hexdigest()


def sms_settings():
    try:
        return (st.secrets.get('TWILIO_ACCOUNT_SID', ''), st.secrets.get('TWILIO_AUTH_TOKEN', ''), st.secrets.get('TWILIO_FROM_NUMBER', ''))
    except Exception:
        return (os.getenv('TWILIO_ACCOUNT_SID', ''), os.getenv('TWILIO_AUTH_TOKEN', ''), os.getenv('TWILIO_FROM_NUMBER', ''))


def normalize_phone(phone):
    phone = re.sub(r'[^\d+]', '', str(phone or ''))
    if re.fullmatch(r'05\d{8}', phone):
        return '+966' + phone[1:]
    if re.fullmatch(r'9665\d{8}', phone):
        return '+' + phone
    return phone if re.fullmatch(r'\+9665\d{8}', phone) else ''


def send_sms(phone, code):
    sid, token, sender = sms_settings()
    if not all((sid, token, sender)):
        raise RuntimeError('خدمة SMS غير مهيأة بعد. يلزم ضبط بيانات Twilio في إعدادات الخادم.')
    url = f'https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json'
    payload = urllib.parse.urlencode({'To': phone, 'From': sender, 'Body': f'Tawazon verification code: {code}. Valid for 5 minutes. Do not share it.'}).encode()
    request = urllib.request.Request(url, data=payload, method='POST')
    request.add_header('Authorization', 'Basic ' + base64.b64encode(f'{sid}:{token}'.encode()).decode())
    request.add_header('Content-Type', 'application/x-www-form-urlencoded')
    with urllib.request.urlopen(request, timeout=12) as response:
        if response.status not in (200, 201):
            raise RuntimeError('تعذر إرسال رسالة التحقق.')


def activate_account():
    st.subheader('تفعيل حسابي لأول مرة')
    st.info('أدخلي رقمك المدرسي. سيصل رمز التحقق برسالة SMS إلى رقم الجوال المسجل لدى المدرسة.')
    username = st.text_input('الرقم المدرسي / رقم المعلمة', key='sms_username').strip()
    if st.button('إرسال رمز SMS', key='send_sms_activation'):
        now = datetime.now(timezone.utc)
        with connect() as c:
            user = c.execute("SELECT id,phone,must_change_password FROM users WHERE username=? AND active=1 AND role IN ('student','teacher')", (username,)).fetchone()
            prior = c.execute('SELECT sent_at FROM sms_verifications WHERE user_id=?', (user['id'],)).fetchone() if user else None
            if prior and (now - datetime.fromisoformat(prior['sent_at'])).total_seconds() < 90:
                st.warning('انتظري 90 ثانية قبل طلب رمز آخر.')
            elif user and user['must_change_password'] and normalize_phone(user['phone']):
                code = f'{secrets.randbelow(1000000):06d}'
                try:
                    send_sms(normalize_phone(user['phone']), code)
                except Exception:
                    st.error('تعذر إرسال الرمز. تأكدي من إعداد خدمة SMS لدى مسؤولة النظام.')
                else:
                    c.execute('''INSERT INTO sms_verifications(user_id,code_hash,expires_at,sent_at,attempts)
                        VALUES(?,?,?,?,0) ON CONFLICT(user_id) DO UPDATE SET
                        code_hash=excluded.code_hash,expires_at=excluded.expires_at,
                        sent_at=excluded.sent_at,attempts=0''',
                        (user['id'], activation_code_hash(code), (now+time_delta(minutes=5)).isoformat(), now.isoformat()))
                    st.success('إذا كان الحساب مؤهلًا، أُرسلت رسالة إلى رقم الجوال المسجل.')
            else:
                st.info('إذا كان الحساب مؤهلًا ورقم الجوال مسجلًا، ستصل رسالة التحقق. عند عدم وصولها راجعي مسؤولة النظام.')
    with st.form('sms_activation_confirm'):
        code = st.text_input('رمز التحقق المرسل إلى الجوال', type='password')
        password = st.text_input('كلمة المرور الجديدة (12 حرفًا على الأقل)', type='password')
        confirm = st.text_input('تأكيد كلمة المرور', type='password')
        submitted = st.form_submit_button('تفعيل الحساب')
    if not submitted:
        return
    if not username or len(password) < 12 or password != confirm or not re.fullmatch(r'\d{6}', code):
        st.error('تأكدي من الرقم والرمز، وأن كلمة المرور 12 حرفًا على الأقل ومطابقة للتأكيد.')
        return
    with connect() as c:
        user = c.execute('''SELECT u.id,u.must_change_password,v.code_hash,v.expires_at,v.attempts
            FROM users u JOIN sms_verifications v ON v.user_id=u.id
            WHERE u.username=? AND u.active=1 AND u.role IN ('student','teacher')''', (username,)).fetchone()
        valid = bool(user and user['must_change_password'] and user['attempts'] < 5 and
            datetime.fromisoformat(user['expires_at']) > datetime.now(timezone.utc) and
            hmac.compare_digest(activation_code_hash(code), user['code_hash']))
        if not valid:
            if user:
                c.execute('UPDATE sms_verifications SET attempts=attempts+1 WHERE user_id=?', (user['id'],))
            st.error('رمز التحقق غير صحيح أو منتهي. اطلبي رمزًا جديدًا.')
            return
        c.execute('UPDATE users SET password_hash=?,must_change_password=0 WHERE id=?', (password_hash(password), user['id']))
        c.execute('DELETE FROM sms_verifications WHERE user_id=?', (user['id'],))
        c.execute('DELETE FROM activation_codes WHERE user_id=?', (user['id'],))
    st.success('تم تفعيل الحساب. سجلي الدخول برقمك المدرسي وكلمة المرور الجديدة.')


def admin_sms_phones():
    st.markdown('#### أرقام الجوال لتفعيل الحسابات عبر SMS')
    st.caption('يُحفظ رقم الجوال من الإدارة فقط، ولا تستطيع الطالبة تغيير وجهة رسالة التفعيل بنفسها.')
    users = fetch("SELECT id,username,full_name,phone,must_change_password FROM users WHERE role IN ('student','teacher') AND active=1 ORDER BY full_name")
    if not users:
        return
    labels = {f"{u['full_name']} ({u['username']})": u for u in users}
    selected = labels[st.selectbox('اختاري حسابًا لإضافة رقم الجوال', list(labels), key='sms_admin_user')]
    with st.form(f"sms_phone_{selected['id']}"):
        phone = st.text_input('رقم الجوال المسجل لدى المدرسة', value=selected.get('phone') or '', placeholder='05xxxxxxxx')
        if st.form_submit_button('حفظ رقم الجوال'):
            normalized = normalize_phone(phone)
            if not normalized:
                st.error('اكتبي رقم جوال سعودي صحيحًا يبدأ بـ 05.')
            else:
                execute('UPDATE users SET phone=? WHERE id=?', (normalized, selected['id']))
                st.success('تم حفظ رقم الجوال.')
    if not all(sms_settings()):
        st.warning('الإرسال الفعلي غير مفعّل بعد. يلزم إعداد مفاتيح Twilio على الخادم؛ لن تظهر رموز التحقق داخل الموقع.')


def admin_activation_codes():
    st.markdown('#### تفعيل حسابات الطالبات والمعلمات')
    st.caption('أنشئي رموز تفعيل لمرة واحدة، ثم سلّمي كل رمز لصاحبة الحساب بشكل خاص. لا يُسمح بتفعيل الحساب بالرقم المدرسي وحده.')
    pending = fetch("SELECT id,username,full_name,role FROM users WHERE role IN ('student','teacher') AND active=1 AND must_change_password=1 ORDER BY role,username")
    mode = st.radio('الحسابات المستهدفة', ['الحسابات المستوردة التي لم تغيّر كلمة المرور', 'حساب محدد للتجربة أو إعادة التفعيل'], horizontal=True, key='activation_mode')
    selected = []
    if mode == 'الحسابات المستوردة التي لم تغيّر كلمة المرور':
        st.write(f'عدد الحسابات المؤهلة: {len(pending)}')
        selected = [u['id'] for u in pending]
    else:
        users = fetch("SELECT id,username,full_name,role FROM users WHERE role IN ('student','teacher') AND active=1 ORDER BY full_name")
        options = {f"{u['full_name']} ({u['username']})": u['id'] for u in users}
        if options:
            choice = st.selectbox('اختاري الحساب', list(options), key='activation_user')
            selected = [options[choice]]
    st.warning('إنشاء رمز جديد يلغي رمز التفعيل السابق للحساب المختار. احفظي ملف الرموز في مكان خاص، ولا تنشريه في مجموعة عامة.')
    if st.button('إنشاء رموز التفعيل', disabled=not selected, key='generate_activation_codes'):
        rows = []
        expires = (datetime.now(timezone.utc) + time_delta(days=30)).isoformat()
        with connect() as c:
            for user_id in selected:
                u = c.execute("SELECT username,full_name,role FROM users WHERE id=? AND active=1 AND role IN ('student','teacher')", (user_id,)).fetchone()
                if not u:
                    continue
                code = secrets.token_hex(8).upper()
                c.execute('''INSERT INTO activation_codes(user_id,code_hash,expires_at,failed_attempts)
                    VALUES(?,?,?,0) ON CONFLICT(user_id) DO UPDATE SET
                    code_hash=excluded.code_hash,expires_at=excluded.expires_at,failed_attempts=0''',
                    (user_id, activation_code_hash(code), expires))
                rows.append({'الاسم': u['full_name'], 'الرقم المدرسي': u['username'], 'النوع': 'طالبة' if u['role']=='student' else 'معلمة', 'رمز التفعيل': code})
        st.session_state.activation_export = pd.DataFrame(rows).to_csv(index=False, encoding='utf-8-sig').encode('utf-8-sig')
        st.success(f'تم إنشاء {len(rows)} رمز تفعيل. حمّلي الملف الآن؛ الرموز لا يمكن عرضها مرة أخرى بعد مغادرة الصفحة.')
    export = st.session_state.get('activation_export')
    if export:
        st.download_button('تحميل رموز التفعيل CSV (خاص بالإدارة)', data=export, file_name='tawazon_activation_codes.csv', mime='text/csv', key='activation_download')
        if st.button('إخفاء ملف الرموز من الجلسة', key='activation_clear'):
            st.session_state.pop('activation_export', None)
            st.rerun()


def enter_demo(role):
    if role == 'admin':
        st.session_state['demo_admin'] = True
        st.session_state.pop('user_id', None)
        st.rerun()
    username = '__tawazon_demo_student__' if role == 'student' else '__tawazon_demo_teacher__'
    display = 'طالبة تجريبية' if role == 'student' else 'معلمة تجريبية'
    with connect() as c:
        row = c.execute('SELECT id FROM users WHERE username=?', (username,)).fetchone()
        if row is None:
            c.execute('INSERT INTO users(username,full_name,password_hash,role,class_name,active,must_change_password) VALUES(?,?,?,?,?,1,0)',
                      (username, display, password_hash(secrets.token_urlsafe(32)), role, '101' if role == 'student' else ''))
            user_id = c.execute('SELECT id FROM users WHERE username=?', (username,)).fetchone()['id']
        else:
            user_id = row['id']
            c.execute('UPDATE users SET active=1,must_change_password=0 WHERE id=?', (user_id,))
        if role == 'teacher':
            c.execute('INSERT OR IGNORE INTO teacher_classes(teacher_id,class_name) VALUES(?,?)', (user_id, '101'))
    st.session_state['user_id'] = user_id
    st.session_state.pop('demo_admin', None)
    st.rerun()


def demo_admin_page():
    with st.sidebar:
        st.title('توازن')
        st.write('مديرة تجريبية')
        st.caption('وضع العرض — دون صلاحية تعديل')
        page = st.radio('القائمة', ['الرئيسية', 'الجداول الدراسية', 'المعلمات المتفرغات', 'إدارة المستخدمين'])
        if st.button('تسجيل الخروج', key='exit_demo_admin', use_container_width=True):
            st.session_state.clear()
            st.rerun()
    st.title('توازن')
    st.info('هذه تجربة للإدارة ببيانات توضيحية فقط. لا يمكن تعديل حسابات المدرسة أو بياناتها.')
    if page == 'الرئيسية':
        st.subheader('لوحة الإدارة')
        a, b, c = st.columns(3)
        a.metric('الطالبات', '150')
        b.metric('المعلمات', '20')
        c.metric('الفصول', '15')
        st.write('من هنا تتابع الإدارة الجداول والفصول والمهام.')
    elif page == 'الجداول الدراسية':
        cls = st.selectbox('اختاري الفصل', SCHOOL_CLASSES, format_func=class_label)
        subjects = ['رياضيات', 'لغة عربية', 'إنجليزي', 'فيزياء', 'كيمياء', 'أحياء', 'حاسب']
        grid = [{'اليوم': day, **{f'الحصة {n}': subjects[(i+n-1)%len(subjects)] for n in PERIODS}} for i, day in enumerate(DAYS)]
        st.caption(f'جدول توضيحي للفصل: {class_label(cls)}')
        st.dataframe(pd.DataFrame(grid), hide_index=True, use_container_width=True)
    elif page == 'المعلمات المتفرغات':
        st.subheader('المعلمات المتفرغات')
        st.write('في النسخة الفعلية تختار المديرة اليوم والحصة لمعرفة المعلمات المتفرغات.')
        st.dataframe(pd.DataFrame({'المعلمة': ['معلمة تجريبية 1', 'معلمة تجريبية 2'], 'الحالة': ['متفرغة', 'متفرغة']}), hide_index=True, use_container_width=True)
    else:
        st.subheader('إدارة المستخدمين')
        st.dataframe(pd.DataFrame({'الاسم': ['طالبة تجريبية', 'معلمة تجريبية'], 'النوع': ['طالبة', 'معلمة'], 'الفصل': ['أول ثانوي 1', 'أول ثانوي 1']}), hide_index=True, use_container_width=True)
        st.caption('إضافة المستخدمين وتعديلهم متاحة لحساب الإدارة الحقيقي فقط.')
    st.markdown('<div style="text-align:center;color:#888;font-size:14px;margin-top:2rem">إعداد الطالبة: لانا سلطان الشهري</div>', unsafe_allow_html=True)

def login():
    st.title('توازن')
    st.subheader('تجربة المشروع')
    st.write('اختاري الصلاحية التي تريدين تجربتها. تبدأ نسخة العرض دون طالبات أو معلمات أو حصص، ويمكنك إضافتها بنفسك.')
    st.warning('نسخة عرض تجريبية: الدخول دون كلمة مرور متاح لأي شخص يملك الرابط. لا تضيفي بيانات حقيقية.')
    admins = fetch("SELECT id FROM users WHERE role='admin' AND username='__demo_admin__' LIMIT 1")
    if not admins:
        create_user('__demo_admin__', 'إدارة المدرسة', secrets.token_urlsafe(32), 'admin')
        admins = fetch("SELECT id FROM users WHERE role='admin' AND username='__demo_admin__' LIMIT 1")
    if st.button('الدخول كمديرة — جميع صلاحيات الإدارة', use_container_width=True, type='primary'):
        st.session_state['user_id'] = admins[0]['id']
        st.rerun()
    teachers = fetch("SELECT id,full_name,username FROM users WHERE role='teacher' AND active=1 ORDER BY full_name")
    students = fetch("SELECT id,full_name,username FROM users WHERE role='student' AND active=1 ORDER BY full_name")
    st.markdown('#### تجربة حساب معلمة')
    if teachers:
        t = st.selectbox('اختاري المعلمة', teachers, format_func=lambda x: f"{x['full_name']} ({x['username']})", key='demo_teacher')
        if st.button('الدخول كمعلمة', use_container_width=True):
            st.session_state['user_id'] = t['id']
            st.rerun()
    else:
        st.info('لا توجد معلمات بعد. ادخلي كمديرة وأضيفي معلمة أولًا.')
    st.markdown('#### تجربة حساب طالبة')
    if students:
        u = st.selectbox('اختاري الطالبة', students, format_func=lambda x: f"{x['full_name']} ({x['username']})", key='demo_student')
        if st.button('الدخول كطالبة', use_container_width=True):
            st.session_state['user_id'] = u['id']
            st.rerun()
    else:
        st.info('لا توجد طالبات بعد. ادخلي كمديرة وأضيفي طالبة أولًا.')

def account_settings(user):
    st.subheader('إعدادات الحساب')
    with st.form('my_account_settings'):
        new_name = st.text_input('الاسم', value=user['full_name'])
        old_password = st.text_input('كلمة المرور الحالية', type='password')
        new_password = st.text_input('كلمة المرور الجديدة (اختياري)', type='password')
        confirm = st.text_input('تأكيد كلمة المرور الجديدة', type='password')
        submitted = st.form_submit_button('حفظ التغييرات')
    if submitted:
        if not new_name.strip():
            st.error('أدخلي الاسم.')
        elif not check_password(old_password, user['password_hash']):
            st.error('كلمة المرور الحالية غير صحيحة.')
        elif new_password and (len(new_password) < 12 or new_password != confirm):
            st.error('كلمة المرور الجديدة يجب أن تكون 12 حرفًا على الأقل ومطابقة للتأكيد.')
        elif not new_password and confirm:
            st.error('أدخلي كلمة المرور الجديدة أولًا.')
        else:
            with connect() as c:
                if new_password:
                    c.execute('UPDATE users SET full_name=?, password_hash=?, must_change_password=0 WHERE id=?',
                              (new_name.strip(), password_hash(new_password), user['id']))
                else:
                    c.execute('UPDATE users SET full_name=? WHERE id=?', (new_name.strip(), user['id']))
            st.success('تم حفظ التغييرات.')
            st.rerun()

def show_timetable(user):
    st.subheader('جدول الحصص الأسبوعي')
    if user['role'] == 'teacher':
        entries = fetch('SELECT t.*, u.full_name teacher FROM timetable t JOIN users u ON u.id=t.teacher_id WHERE t.teacher_id=?', (user['id'],))
    else:
        permitted = allowed_classes(user)
        if not permitted:
            st.info('لم يُحدد فصل لهذا الحساب بعد.')
            return
        selected = st.selectbox('الفصل', permitted, key='table_class', format_func=class_label) if user['role'] == 'admin' else permitted[0]
        entries = fetch('SELECT t.*, u.full_name teacher FROM timetable t JOIN users u ON u.id=t.teacher_id WHERE t.class_name=?', (selected,))
    grid = []
    for day in DAYS:
        row = {'اليوم': day}
        for p in PERIODS:
            found = next((e for e in entries if e['day'] == day and e['period'] == p), None)
            if found:
                row[f'الحصة {p}'] = (f"{found['subject']}\n{class_label(found['class_name'])}" if user['role'] == 'teacher' else f"{found['subject']}\n{found['teacher']}")
            else:
                row[f'الحصة {p}'] = '—'
        grid.append(row)
    st.dataframe(pd.DataFrame(grid), hide_index=True, width='stretch')

def admin_users():
    st.subheader('إدارة المستخدمين والصلاحيات')
    role_labels = {'admin': 'إدارة', 'teacher': 'معلمة', 'student': 'طالبة'}
    with st.form('add_user', clear_on_submit=True):
        a, b = st.columns(2)
        role_label = a.selectbox('نوع الحساب', ['طالبة', 'معلمة', 'إدارة'])
        role = {'طالبة': 'student', 'معلمة': 'teacher', 'إدارة': 'admin'}[role_label]
        name = b.text_input('الاسم الكامل')
        username = a.text_input('اسم المستخدم / الرقم المدرسي')
        pw = b.text_input('كلمة مرور (اختياري في نسخة العرض)', type='password')
        class_name = a.selectbox('الفصل (للطالبة فقط)', SCHOOL_CLASSES, format_func=class_label) if role == 'student' else ''
        if st.form_submit_button('إضافة الحساب'):
            if not username.strip() or not name.strip() or (pw and len(pw) < 12) or (role == 'student' and not class_name.strip()):
                st.error('أكملي الحقول المطلوبة. كلمة المرور 12 حرفًا على الأقل.')
            else:
                try:
                    create_user(username, name, pw or secrets.token_urlsafe(24), role, class_name)
                    st.success('تمت إضافة الحساب.')
                    st.rerun()
                except sqlite3.IntegrityError:
                    st.error('اسم المستخدم موجود مسبقًا.')
    st.info('لإضافة الطالبات والمعلمات دفعة واحدة، افتحي «تهيئة المدرسة» من القائمة.')
    if not DEMO_MODE:
        admin_sms_phones()
    st.markdown('#### الحسابات')
    users = fetch('SELECT id,username,full_name,role,class_name,active FROM users ORDER BY role,full_name')
    st.dataframe(pd.DataFrame([{'المعرف': u['id'], 'المستخدم': u['username'], 'الاسم': u['full_name'], 'الصلاحية': role_labels[u['role']], 'الفصل': class_label(u['class_name']), 'الحالة': 'نشط' if u['active'] else 'موقوف'} for u in users]), hide_index=True, width='stretch')
    options = {f"{u['full_name']} ({u['username']})": u for u in users}
    chosen = st.selectbox('تعديل حساب', list(options), key='edit_user') if options else None
    if chosen:
        u = options[chosen]
        with st.form('edit_account'):
            new_name = st.text_input('الاسم الكامل', value=u['full_name'])
            new_username = st.text_input('اسم المستخدم أو الرقم المدرسي', value=u['username'])
            new_role = st.selectbox('الصلاحية', ['student', 'teacher', 'admin'], index=['student', 'teacher', 'admin'].index(u['role']), format_func=lambda r: role_labels[r])
            new_class = st.selectbox('الفصل (للطالبة)', SCHOOL_CLASSES, index=SCHOOL_CLASSES.index(canonical_class(u['class_name'])) if canonical_class(u['class_name']) in SCHOOL_CLASSES else 0, format_func=class_label) if new_role == 'student' else ''
            active = st.checkbox('الحساب نشط', value=bool(u['active']))
            new_password = st.text_input('كلمة مرور جديدة (اختياري)', type='password')
            if st.form_submit_button('حفظ التعديلات'):
                current_id = st.session_state.user_id
                if not new_name.strip() or not new_username.strip():
                    st.error('الاسم واسم المستخدم مطلوبان.')
                elif u['id'] == current_id and (new_role != 'admin' or not active):
                    st.error('لا يمكنك سحب صلاحية الإدارة أو إيقاف حسابك الحالي.')
                elif new_role == 'student' and not new_class.strip():
                    st.error('حددي فصل الطالبة.')
                elif new_password and len(new_password) < 12:
                    st.error('كلمة المرور الجديدة يجب أن تكون 12 حرفًا على الأقل.')
                else:
                    try:
                        execute('UPDATE users SET username=?,full_name=?,role=?,class_name=?,active=? WHERE id=?', (new_username.strip(), new_name.strip(), new_role, new_class.strip() if new_role == 'student' else '', int(active), u['id']))
                    except sqlite3.IntegrityError:
                        st.error('اسم المستخدم مستخدم مسبقًا.')
                        st.stop()
                    if new_password:
                        execute('UPDATE users SET password_hash=?,must_change_password=1 WHERE id=?', (password_hash(new_password), u['id']))
                    if new_role != 'teacher':
                        execute('DELETE FROM teacher_classes WHERE teacher_id=?', (u['id'],))
                    st.success('تم تحديث الحساب.')
                    st.rerun()
    st.markdown('#### 🗑️ حذف حساب')
    st.caption('الحذف متاح للمديرة فقط. لا يمكن حذف حساب المديرة المستخدمة حاليًا، ولا حذف معلمة مرتبطة بحصص أو واجبات قبل معالجة ارتباطاتها.')
    deletable = [u for u in users if u['id'] != st.session_state.get('user_id')]
    if deletable:
        delete_options = {f"{role_labels[u['role']]} — {u['full_name']} ({u['username']})": u for u in deletable}
        delete_key = st.selectbox('اختاري الحساب المراد حذفه', list(delete_options), key='delete_user_choice')
        target = delete_options[delete_key]
        if target['role'] == 'teacher':
            lesson_count = fetch('SELECT COUNT(*) n FROM timetable WHERE teacher_id=?', (target['id'],))[0]['n']
            task_count = fetch('SELECT COUNT(*) n FROM tasks WHERE teacher_id=?', (target['id'],))[0]['n']
            if lesson_count or task_count:
                st.warning(f'لا يمكن حذف هذه المعلمة الآن؛ مرتبطة بـ {lesson_count} حصة و{task_count} واجب/اختبار. احذفي أو أعيدي إسناد هذه العناصر أولًا حتى لا يتأثر الجدول.')
        st.warning(f"سيُحذف حساب: {target['full_name']} — {role_labels[target['role']]}.")
        with st.form('confirm_delete_user'):
            confirmed = st.checkbox('أؤكد أنني أريد حذف هذا الحساب نهائيًا')
            submitted = st.form_submit_button('🗑️ حذف الحساب المحدد')
            if submitted:
                if not confirmed:
                    st.error('فعّلي مربع التأكيد أولًا.')
                elif target['id'] == st.session_state.get('user_id'):
                    st.error('لا يمكنك حذف حسابك الحالي.')
                else:
                    try:
                        with connect() as c:
                            if target['role'] == 'admin':
                                admin_count = c.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND active=1").fetchone()[0]
                                if admin_count <= 1:
                                    raise ValueError('لا يمكن حذف آخر حساب إدارة نشط.')
                            if target['role'] == 'teacher':
                                has_lessons = c.execute('SELECT 1 FROM timetable WHERE teacher_id=? LIMIT 1', (target['id'],)).fetchone()
                                has_tasks = c.execute('SELECT 1 FROM tasks WHERE teacher_id=? LIMIT 1', (target['id'],)).fetchone()
                                if has_lessons or has_tasks:
                                    raise ValueError('المعلمة مرتبطة بحصص أو واجبات؛ يجب معالجة هذه الارتباطات أولًا.')
                            c.execute('DELETE FROM sms_verifications WHERE user_id=?', (target['id'],))
                            c.execute('DELETE FROM activation_codes WHERE user_id=?', (target['id'],))
                            c.execute('DELETE FROM users WHERE id=?', (target['id'],))
                        st.success('تم حذف الحساب بنجاح.')
                        st.rerun()
                    except (sqlite3.IntegrityError, ValueError) as exc:
                        st.error(f'تعذر حذف الحساب: {exc}')

    st.markdown('#### ربط المعلمات بالفصول')
    teachers = fetch('SELECT id,full_name,username FROM users WHERE role="teacher" AND active=1 ORDER BY full_name')
    teacher_map = {f"{t['full_name']} ({t['username']})": t['id'] for t in teachers}
    if teacher_map:
        teacher_label = st.selectbox('المعلمة', list(teacher_map), key='assign_teacher')
        teacher_id = teacher_map[teacher_label]
        existing = [x['class_name'] for x in fetch('SELECT class_name FROM teacher_classes WHERE teacher_id=?', (teacher_id,))]
        choices = classes()
        selected = st.multiselect('الفصول المسموح لها بإدارتها', choices, default=[x for x in existing if x in choices], format_func=class_label)
        new_class = ''
        if st.button('حفظ فصول المعلمة'):
            selected = sorted(set(selected + ([new_class.strip()] if new_class.strip() else [])))
            with connect() as c:
                c.execute('DELETE FROM teacher_classes WHERE teacher_id=?', (teacher_id,))
                c.executemany('INSERT INTO teacher_classes(teacher_id,class_name) VALUES(?,?)', [(teacher_id, x) for x in selected])
            st.success('تم حفظ الفصول.')
            st.rerun()

def admin_timetable():
    st.subheader('إدارة الجداول الدراسية')
    teacher_rows = fetch('SELECT id,username,full_name FROM users WHERE role="teacher" AND active=1 ORDER BY full_name')
    teacher_map = {f"{t['full_name']} ({t['username']})": t['id'] for t in teacher_rows}
    all_classes = classes()
    view_tab, add_tab, delete_tab = st.tabs(['عرض جداول الفصول والمعلمات', 'إضافة حصة', 'حذف حصة'])

    with view_tab:
        total = fetch('SELECT COUNT(*) AS n FROM timetable')[0]['n']
        st.caption(f'إجمالي الحصص المسجلة: {total}')
        view_type = st.radio('عرض الجدول حسب', ['الفصل', 'المعلمة'], horizontal=True, key='admin_view_type')
        if view_type == 'الفصل':
            timetable_classes = [c for c in SCHOOL_CLASSES if fetch('SELECT 1 FROM timetable WHERE class_name=? LIMIT 1', (c,))]
            if not timetable_classes:
                st.info('لا توجد جداول فصول مسجلة بعد.')
            else:
                chosen_class = st.selectbox('اختاري الفصل', timetable_classes, key='admin_view_class', format_func=class_label)
                entries = fetch('SELECT t.*,u.full_name teacher FROM timetable t JOIN users u ON u.id=t.teacher_id WHERE t.class_name=?', (chosen_class,))
                grid = []
                for day in DAYS:
                    row = {'اليوم': day}
                    for p in PERIODS:
                        lesson = next((x for x in entries if x['day'] == day and x['period'] == p), None)
                        row[f'الحصة {p}'] = f"{lesson['subject']} - {lesson['teacher']}" if lesson else 'فراغ'
                    grid.append(row)
                df = pd.DataFrame(grid)
                st.dataframe(df, hide_index=True, use_container_width=True)
                st.download_button('تحميل جدول الفصل CSV', df.to_csv(index=False).encode('utf-8-sig'), f'class_{chosen_class}.csv', mime='text/csv')
        else:
            if not teacher_rows:
                st.info('لا توجد معلمات نشطات.')
            else:
                selected_teacher = st.selectbox('اختاري المعلمة', teacher_rows, format_func=lambda t: f"{t['full_name']} ({t['username']})", key='admin_view_teacher')
                entries = fetch('SELECT * FROM timetable WHERE teacher_id=?', (selected_teacher['id'],))
                grid = []
                for day in DAYS:
                    row = {'اليوم': day}
                    for p in PERIODS:
                        lesson = next((x for x in entries if x['day'] == day and x['period'] == p), None)
                        row[f'الحصة {p}'] = f"{lesson['subject']} - {class_label(lesson['class_name'])}" if lesson else 'فراغ'
                    grid.append(row)
                df = pd.DataFrame(grid)
                st.dataframe(df, hide_index=True, use_container_width=True)
                st.download_button('تحميل جدول المعلمة CSV', df.to_csv(index=False).encode('utf-8-sig'), f'teacher_{selected_teacher["username"]}.csv', mime='text/csv')

    with add_tab:
        if not teacher_map:
            st.info('أضيفي معلمة أولًا من إدارة المستخدمين.')
        else:
            st.info('اختاري فصلًا وحصة فارغة. إذا كانت الحصة مشغولة، استخدمي تعديل الحصة أسفل الصفحة بدل الإضافة.')
            with st.form('new_lesson'):
                a, b, c = st.columns(3)
                if all_classes:
                    selected_class = a.selectbox('الفصل', all_classes, format_func=class_label)
                    new_class = ''
                else:
                    selected_class = ''
                    new_class = ''
                day = b.selectbox('اليوم', DAYS)
                period = c.selectbox('الحصة', PERIODS)
                subject = a.text_input('المادة')
                teacher_label = b.selectbox('المعلمة', list(teacher_map))
                if st.form_submit_button('إضافة الحصة'):
                    teacher_id = teacher_map[teacher_label]
                    class_name = new_class.strip() or selected_class
                    if not class_name or not subject.strip():
                        st.error('حددي الفصل والمادة.')
                    elif fetch('SELECT 1 FROM timetable WHERE class_name=? AND day=? AND period=?', (class_name, day, period)):
                        st.error('الفصل لديه حصة بالفعل في هذا الموعد. اختاري حصة فارغة أو عدّلي الحصة الموجودة.')
                    elif fetch('SELECT 1 FROM timetable WHERE teacher_id=? AND day=? AND period=?', (teacher_id, day, period)):
                        st.error('المعلمة لديها حصة أخرى في هذا الموعد. اختاري معلمة متفرغة.')
                    else:
                        try:
                            with connect() as conn:
                                conn.execute('INSERT INTO timetable(class_name,day,period,subject,teacher_id) VALUES(?,?,?,?,?)', (class_name, day, period, subject.strip(), teacher_id))
                                conn.execute('INSERT OR IGNORE INTO teacher_classes(teacher_id,class_name) VALUES(?,?)', (teacher_id, class_name))
                            st.success('تمت إضافة الحصة وربط المعلمة بالفصل.')
                            st.rerun()
                        except sqlite3.IntegrityError:
                            st.error('تعذر الإضافة بسبب تعارض في الجدول. حدّثي الصفحة وحاولي مرة أخرى.')

    with delete_tab:
        entries = fetch('SELECT t.id,t.class_name,t.day,t.period,t.subject,u.full_name teacher FROM timetable t JOIN users u ON u.id=t.teacher_id ORDER BY t.class_name,t.day,t.period')
        if any(x['class_name'] in SCHOOL_CLASSES for x in entries):
            filter_classes = [c for c in SCHOOL_CLASSES if any(x['class_name'] == c for x in entries)]
            chosen = st.selectbox('الفصل المراد تعديل حصصه', filter_classes, key='delete_class_filter', format_func=class_label)
            filtered = [x for x in entries if x['class_name'] == chosen]
            st.dataframe(pd.DataFrame([{'الفصل': class_label(x['class_name']), 'اليوم': x['day'], 'الحصة': x['period'], 'المادة': x['subject'], 'المعلمة': x['teacher']} for x in filtered]), hide_index=True, use_container_width=True)
            to_delete = st.selectbox('اختاري الحصة للحذف', filtered, format_func=lambda x: f"{x['day']} - الحصة {x['period']} - {x['subject']} - {x['teacher']}")
            confirm = st.checkbox('أؤكد حذف الحصة المحددة', key='confirm_delete_lesson')
            if st.button('حذف الحصة المحددة', disabled=not confirm):
                execute('DELETE FROM timetable WHERE id=?', (to_delete['id'],))
                st.success('تم حذف الحصة.')
                st.rerun()
        else:
            st.info('لا توجد حصص للحذف.')

def tasks_page(user):
    st.subheader('الواجبات والاختبارات')
    permitted = allowed_classes(user)
    if user['role'] == 'student':
        rows = fetch('SELECT t.*,u.full_name teacher FROM tasks t JOIN users u ON u.id=t.teacher_id WHERE t.class_name=? ORDER BY t.due_date,t.id', (user['class_name'],))
    elif user['role'] == 'teacher':
        rows = fetch('SELECT t.*,u.full_name teacher FROM tasks t JOIN users u ON u.id=t.teacher_id WHERE t.teacher_id=? ORDER BY t.due_date,t.id', (user['id'],))
    else:
        rows = fetch('SELECT t.*,u.full_name teacher FROM tasks t JOIN users u ON u.id=t.teacher_id ORDER BY t.due_date,t.id')
    if rows:
        completed = {x['task_id'] for x in fetch('SELECT task_id FROM completions WHERE student_id=?', (user['id'],))} if user['role'] == 'student' else set()
        for t in rows:
            with st.expander(f"{t['kind']} | {t['title']} | {t['class_name']} | {t['due_date']}"):
                st.write(f"المادة: {t['subject']} | المعلمة: {t['teacher']}")
                if t['details']:
                    st.write(t['details'])
                if user['role'] == 'student':
                    done = st.checkbox('تم الإنجاز', value=t['id'] in completed, key=f"done_{t['id']}")
                    if done and t['id'] not in completed:
                        execute('INSERT OR IGNORE INTO completions(student_id,task_id) VALUES(?,?)', (user['id'], t['id']))
                        st.rerun()
                    if not done and t['id'] in completed:
                        execute('DELETE FROM completions WHERE student_id=? AND task_id=?', (user['id'], t['id']))
                        st.rerun()
                elif user['role'] == 'admin' or t['teacher_id'] == user['id']:
                    if st.button('حذف', key=f"del_task_{t['id']}"):
                        execute('DELETE FROM tasks WHERE id=?', (t['id'],))
                        st.rerun()
    else:
        st.info('لا توجد واجبات أو اختبارات حتى الآن.')
    if user['role'] == 'student':
        return
    st.markdown('#### إضافة واجب أو اختبار')
    if not permitted:
        st.info('اربطي المعلمة بفصل من لوحة الإدارة أولًا.')
        return
    with st.form('new_task'):
        a, b = st.columns(2)
        title = a.text_input('العنوان')
        subject = b.text_input('المادة')
        kind = a.selectbox('النوع', ['واجب', 'اختبار'])
        class_name = b.selectbox('الفصل', permitted)
        due = a.date_input('الموعد', value=date.today() + timedelta(days=1))
        details = st.text_area('التفاصيل (اختياري)')
        teacher_choices = fetch('SELECT u.id,u.full_name FROM users u JOIN teacher_classes tc ON tc.teacher_id=u.id WHERE u.role="teacher" AND u.active=1 AND tc.class_name=? ORDER BY u.full_name', (class_name,)) if user['role']=='admin' else []
        chosen_teacher = st.selectbox('المعلمة المسؤولة', teacher_choices, format_func=lambda t: t['full_name']) if user['role']=='admin' and teacher_choices else None
        if user['role']=='admin' and not teacher_choices:
            st.caption('لا توجد معلمة مربوطة بالفصل المختار؛ اربطي معلمة بالفصل أولًا.')
        if st.form_submit_button('نشر'):
            if not title.strip() or not subject.strip():
                st.error('اكتبي العنوان والمادة.')
            elif user['role']=='admin' and not chosen_teacher:
                st.error('يجب تحديد معلمة مسؤولة عن المهمة.')
            else:
                conflicts = fetch('SELECT title,subject FROM tasks WHERE class_name=? AND due_date=? AND kind="اختبار"', (class_name, due.isoformat())) if kind == 'اختبار' else []
                if conflicts:
                    st.warning('تنبيه: يوجد اختبار آخر لهذا الفصل في اليوم نفسه: ' + '، '.join(x['subject'] for x in conflicts))
                st.session_state.pending_task = {'title': title.strip(), 'subject': subject.strip(), 'kind': kind, 'class_name': class_name, 'due': due.isoformat(), 'details': details.strip(), 'teacher_id': chosen_teacher['id'] if user['role']=='admin' else user['id']}
                if not conflicts:
                    save_task()
    pending = st.session_state.get('pending_task')
    if pending:
        st.info(f"طلب نشر: {pending['title']} — {pending['class_name']} — {pending['due']}")
        if st.button('تأكيد نشر المهمة رغم التعارض' if pending['kind'] == 'اختبار' else 'تأكيد النشر'):
            save_task()
        if st.button('إلغاء الطلب'):
            st.session_state.pop('pending_task', None)
            st.rerun()

def save_task():
    p = st.session_state.pop('pending_task')
    current = fetch('SELECT role FROM users WHERE id=? AND active=1', (st.session_state.user_id,))
    if not current or current[0]['role'] not in ('admin', 'teacher'):
        st.error('لا توجد صلاحية للنشر.')
        return
    if current[0]['role'] == 'teacher' and p['class_name'] not in allowed_classes({'role': 'teacher', 'id': st.session_state.user_id}):
        st.error('هذا الفصل غير مصرح به.')
        return
    execute('INSERT INTO tasks(title,subject,kind,class_name,due_date,details,teacher_id) VALUES(?,?,?,?,?,?,?)', (p['title'], p['subject'], p['kind'], p['class_name'], p['due'], p['details'], p['teacher_id']))
    st.success('تم النشر.')
    st.rerun()


def free_teachers():
    st.subheader('المعلمات المتفرغات')
    a, b = st.columns(2)
    day = a.selectbox('اليوم', DAYS, key='free_day')
    period = b.selectbox('الحصة', PERIODS, key='free_period')
    rows = fetch('''SELECT u.id,u.full_name,u.username FROM users u
        WHERE u.role='teacher' AND u.active=1
        AND NOT EXISTS (SELECT 1 FROM timetable t WHERE t.teacher_id=u.id AND t.day=? AND t.period=?)
        ORDER BY u.full_name''', (day, period))
    st.metric('عدد المعلمات المتفرغات', len(rows))
    if rows:
        st.dataframe(pd.DataFrame([{'المعلمة': x['full_name'], 'الرقم': x['username']} for x in rows]), hide_index=True, width='stretch')
    else:
        st.info('لا توجد معلمات متفرغات في هذه الحصة.')
    st.markdown('#### إشغال المعلمات خلال الأسبوع')
    teachers = fetch('SELECT id,full_name FROM users WHERE role="teacher" AND active=1 ORDER BY full_name')
    if teachers:
        selected = st.selectbox('المعلمة', teachers, format_func=lambda x: x['full_name'], key='free_teacher')
        lessons = fetch('SELECT day,period,class_name,subject FROM timetable WHERE teacher_id=?', (selected['id'],))
        grid = []
        for day_name in DAYS:
            row = {'اليوم': day_name}
            for n in PERIODS:
                item = next((x for x in lessons if x['day']==day_name and x['period']==n), None)
                row[f'الحصة {n}'] = f"{item['subject']} - {class_label(item['class_name'])}" if item else 'فراغ'
            grid.append(row)
        st.dataframe(pd.DataFrame(grid), hide_index=True, width='stretch')

def edit_lessons():
    st.markdown('#### تعديل حصة موجودة')
    entries = fetch('SELECT t.*,u.full_name teacher FROM timetable t JOIN users u ON u.id=t.teacher_id ORDER BY t.id DESC')
    if not entries:
        return
    selected = st.selectbox('اختاري الحصة', entries, format_func=lambda x: f"{class_label(x['class_name'])} | {x['day']} | {x['period']} | {x['subject']} | {x['teacher']}", key='edit_lesson')
    teachers = fetch('SELECT id,full_name FROM users WHERE role="teacher" AND active=1 ORDER BY full_name')
    with st.form('edit_lesson_form'):
        a,b,c = st.columns(3)
        cls = a.selectbox('الفصل', SCHOOL_CLASSES, index=SCHOOL_CLASSES.index(canonical_class(selected['class_name'])) if canonical_class(selected['class_name']) in SCHOOL_CLASSES else 0, format_func=class_label)
        day = b.selectbox('اليوم', DAYS, index=DAYS.index(selected['day']))
        period = c.selectbox('الحصة', PERIODS, index=PERIODS.index(selected['period']))
        subject = a.text_input('المادة', selected['subject'])
        idx = next((i for i,t in enumerate(teachers) if t['id']==selected['teacher_id']), 0)
        teacher = b.selectbox('المعلمة', teachers, index=idx, format_func=lambda x:x['full_name'])
        if st.form_submit_button('حفظ تعديل الحصة'):
            if not cls.strip() or not subject.strip():
                st.error('الفصل والمادة مطلوبان.')
            else:
                try:
                    with connect() as conn:
                        conn.execute('UPDATE timetable SET class_name=?,day=?,period=?,subject=?,teacher_id=? WHERE id=?', (cls.strip(),day,period,subject.strip(),teacher['id'],selected['id']))
                        conn.execute('INSERT OR IGNORE INTO teacher_classes(teacher_id,class_name) VALUES(?,?)', (teacher['id'],cls.strip()))
                    st.success('تم التعديل.')
                    st.rerun()
                except sqlite3.IntegrityError:
                    st.error('تعارض: المعلمة أو الفصل مشغولان في الحصة نفسها.')

def bulk_lessons():
    st.info('استيراد الجدول والتحقق من التعارضات متاحان في صفحة «تهيئة المدرسة».')

def edit_tasks(user):
    if user['role']=='student':
        return
    st.markdown('#### تعديل واجب أو اختبار')
    if user['role']=='admin':
        tasks = fetch('SELECT * FROM tasks ORDER BY due_date DESC,id DESC')
    else:
        tasks = fetch('SELECT * FROM tasks WHERE teacher_id=? ORDER BY due_date DESC,id DESC', (user['id'],))
    if not tasks:
        return
    selected = st.selectbox('المهمة', tasks, format_func=lambda x: f"{x['title']} | {x['class_name']} | {x['due_date']}", key='task_to_edit')
    with st.form('edit_task_form'):
        a,b = st.columns(2)
        title = a.text_input('العنوان', selected['title'])
        subject = b.text_input('المادة', selected['subject'])
        kind = a.selectbox('النوع', ['واجب','اختبار'], index=['واجب','اختبار'].index(selected['kind']))
        due = b.date_input('الموعد', value=date.fromisoformat(selected['due_date']))
        details = st.text_area('التفاصيل', selected['details'])
        if st.form_submit_button('حفظ تعديل المهمة'):
            if not title.strip() or not subject.strip():
                st.error('العنوان والمادة مطلوبان.')
            else:
                conflicts = fetch('SELECT subject FROM tasks WHERE id<>? AND class_name=? AND due_date=? AND kind="اختبار"',(selected['id'],selected['class_name'],due.isoformat())) if kind=='اختبار' else []
                if conflicts:
                    st.error('يوجد اختبار آخر في هذا اليوم للفصل نفسه. اختاري موعدًا آخر.')
                else:
                    execute('UPDATE tasks SET title=?,subject=?,kind=?,due_date=?,details=? WHERE id=?',(title.strip(),subject.strip(),kind,due.isoformat(),details.strip(),selected['id']))
                    st.success('تم تعديل المهمة.')
                    st.rerun()

def reports():
    st.subheader('التقارير والإحصائيات')
    stats = fetch('SELECT role,COUNT(*) n FROM users WHERE active=1 GROUP BY role')
    counts = {x['role']:x['n'] for x in stats}
    a,b,c,d = st.columns(4)
    a.metric('الطالبات', counts.get('student',0))
    b.metric('المعلمات', counts.get('teacher',0))
    c.metric('الحصص المجدولة', fetch('SELECT COUNT(*) n FROM timetable')[0]['n'])
    d.metric('الواجبات والاختبارات', fetch('SELECT COUNT(*) n FROM tasks')[0]['n'])
    st.markdown('#### كثافة الاختبارات حسب الفصل والتاريخ')
    density = fetch('SELECT class_name,due_date,COUNT(*) n FROM tasks WHERE kind="اختبار" GROUP BY class_name,due_date ORDER BY due_date')
    if density:
        st.dataframe(pd.DataFrame([{'الفصل':class_label(x['class_name']),'التاريخ':x['due_date'],'عدد الاختبارات':x['n'],'تنبيه':'تعارض' if x['n']>1 else '—'} for x in density]),hide_index=True,width='stretch')
    st.markdown('#### متابعة إنجاز الواجبات')
    progress = fetch('''SELECT t.title,t.class_name,t.due_date,
      (SELECT COUNT(*) FROM users u WHERE u.role='student' AND u.active=1 AND u.class_name=t.class_name) total,
      (SELECT COUNT(*) FROM completions c JOIN users u ON u.id=c.student_id WHERE c.task_id=t.id AND u.active=1 AND u.class_name=t.class_name) done
      FROM tasks t WHERE t.kind='واجب' ORDER BY t.due_date DESC''')
    if progress:
        st.dataframe(pd.DataFrame([{'الواجب':x['title'],'الفصل':class_label(x['class_name']),'الموعد':x['due_date'],'الطالبات':x['total'],'المنجزات':x['done'],'نسبة الإنجاز':f"{round(100*x['done']/x['total']) if x['total'] else 0}%"} for x in progress]),hide_index=True,width='stretch')
    st.markdown('#### تنزيل بيانات التقارير')
    for label, query, filename in [
        ('الحسابات','SELECT username,full_name,role,class_name,active FROM users','users_report.csv'),
        ('الجداول','SELECT t.class_name,t.day,t.period,t.subject,u.full_name teacher FROM timetable t JOIN users u ON u.id=t.teacher_id','timetable_report.csv'),
        ('المهام','SELECT title,subject,class_name,kind,due_date,details FROM tasks','tasks_report.csv')]:
        data = fetch(query)
        if data:
            st.download_button('تنزيل '+label, pd.DataFrame(data).to_csv(index=False).encode('utf-8-sig'), filename, mime='text/csv', key=filename)

def teacher_dashboard(user):
    st.subheader('ملخص المعلمة')
    a,b,c = st.columns(3)
    a.metric('الفصول',len(allowed_classes(user)))
    b.metric('حصصي الأسبوعية',fetch('SELECT COUNT(*) n FROM timetable WHERE teacher_id=?',(user['id'],))[0]['n'])
    c.metric('المهام المنشورة',fetch('SELECT COUNT(*) n FROM tasks WHERE teacher_id=?',(user['id'],))[0]['n'])
    st.markdown('#### حصصي اليوم')
    day_index = (date.today().weekday()+1)%7
    today = DAYS[day_index] if day_index < 5 else None
    if today:
        rows=fetch('SELECT period,class_name,subject FROM timetable WHERE teacher_id=? AND day=? ORDER BY period',(user['id'],today))
        if rows:
            st.dataframe(pd.DataFrame([{'الحصة':x['period'],'الفصل':class_label(x['class_name']),'المادة':x['subject']} for x in rows]),hide_index=True,width='stretch')
        else:
            st.info('لا توجد حصص مسجلة لهذا اليوم.')
    else:
        st.info('اليوم عطلة أسبوعية.')

def student_dashboard(user):
    st.subheader('ملخص الطالبة')
    st.write('الفصل: '+(class_label(user['class_name']) or 'لم يحدد'))
    tasks=fetch('SELECT id,kind,title,due_date FROM tasks WHERE class_name=? ORDER BY due_date',(user['class_name'],))
    completed={x['task_id'] for x in fetch('SELECT task_id FROM completions WHERE student_id=?',(user['id'],))}
    a,b,c=st.columns(3)
    a.metric('المهام',len(tasks))
    b.metric('المهام المنجزة',len(completed & {t['id'] for t in tasks}))
    c.metric('الاختبارات القادمة',sum(t['kind']=='اختبار' and t['due_date']>=date.today().isoformat() for t in tasks))
    upcoming=[x for x in tasks if x['due_date']>=date.today().isoformat()][:7]
    if upcoming:
        st.markdown('#### المواعيد القادمة')
        st.dataframe(pd.DataFrame([{'النوع':x['kind'],'المهمة':x['title'],'الموعد':x['due_date']} for x in upcoming]),hide_index=True,width='stretch')



def forced_password_change(user):
    st.warning('يجب تغيير كلمة المرور المؤقتة قبل استخدام الحساب.')
    with st.form('first_password_change'):
        current = st.text_input('كلمة المرور المؤقتة', type='password')
        new = st.text_input('كلمة المرور الجديدة (12 حرفًا على الأقل)', type='password')
        confirm = st.text_input('تأكيد كلمة المرور الجديدة', type='password')
        if st.form_submit_button('حفظ كلمة المرور'):
            if not check_password(current, user['password_hash']):
                st.error('كلمة المرور المؤقتة غير صحيحة.')
            elif len(new) < 12 or new != confirm or new == current:
                st.error('اختاري كلمة مرور جديدة مختلفة من 12 حرفًا على الأقل وأكديها.')
            else:
                execute('UPDATE users SET password_hash=?,must_change_password=0 WHERE id=?', (password_hash(new), user['id']))
                st.success('تم تغيير كلمة المرور.')
                st.rerun()


def xlsx_template(columns, example):
    buffer = BytesIO()
    with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
        pd.DataFrame([example], columns=columns).to_excel(writer, index=False, sheet_name='بيانات')
    return buffer.getvalue()


def clean_cell(value):
    return str(value).strip().replace('\u200f', '').replace('\u200e', '')


def read_sheet(upload, required):
    frame = pd.read_excel(upload, dtype=str, engine='openpyxl', keep_default_na=False)
    frame.columns = [clean_cell(c) for c in frame.columns]
    missing = [c for c in required if c not in frame.columns]
    if missing:
        raise ValueError('أعمدة ناقصة: ' + '، '.join(missing))
    if len(frame) > 20000:
        raise ValueError('الحد الأقصى 20000 صف في الملف الواحد.')
    return [{c: clean_cell(row[c]) for c in required} for _, row in frame.iterrows()]


def validate_people(rows, role):
    errors, accepted, seen = [], [], set()
    for number, row in enumerate(rows, 2):
        username = row['الرقم المدرسي'] if role == 'student' else row['رقم المعلمة']
        name = row['الاسم']
        cls = canonical_class(row.get('الفصل', ''))
        if not username or not name or (role == 'student' and not cls):
            errors.append(f'الصف {number}: بيانات مطلوبة ناقصة')
        elif username in seen:
            errors.append(f'الصف {number}: رقم مكرر في الملف ({username})')
        elif len(username) > 100 or len(name) > 200 or len(cls) > 150:
            errors.append(f'الصف {number}: نص طويل جدًا')
        else:
            accepted.append((username, name, cls))
            seen.add(username)
    return accepted, errors


def import_people(rows, role):
    accepted, errors = validate_people(rows, role)
    if errors:
        return [], errors, 0
    created, skipped = [], 0
    with connect() as c:
        for username, name, cls in accepted:
            old = c.execute('SELECT id FROM users WHERE username=?', (username,)).fetchone()
            if old:
                skipped += 1
                continue
            temporary = secrets.token_urlsafe(15)
            c.execute('INSERT INTO users(username,full_name,password_hash,role,class_name,active,must_change_password) VALUES(?,?,?,?,?,1,1)',
                      (username, name, password_hash(temporary), role, cls))
            created.append({'اسم المستخدم': username, 'الاسم': name, 'كلمة المرور المؤقتة': temporary})
    return created, [], skipped


def parse_period(raw):
    raw = clean_cell(raw)
    if not re.fullmatch(r'[1-7](?:\.0)?', raw):
        raise ValueError('الحصة يجب أن تكون رقمًا من 1 إلى 7')
    return int(float(raw))


def validate_timetable(rows, replace_existing=False):
    errors, prepared = [], []
    occupied_class, occupied_teacher = set(), set()
    with connect() as c:
        teachers = {x['username']: x['id'] for x in c.execute("SELECT id,username FROM users WHERE role='teacher' AND active=1")}
        existing_class = set() if replace_existing else {(x['class_name'], x['day'], x['period']) for x in c.execute('SELECT class_name,day,period FROM timetable')}
        existing_teacher = set() if replace_existing else {(x['teacher_id'], x['day'], x['period']) for x in c.execute('SELECT teacher_id,day,period FROM timetable')}
    for number, row in enumerate(rows, 2):
        cls, day, subject, username = (row[k] for k in ('الفصل', 'اليوم', 'المادة', 'رقم المعلمة'))
        cls = canonical_class(cls)
        try:
            period = parse_period(row['الحصة'])
            if not cls or not subject or not username or day not in DAYS:
                raise ValueError('بيانات ناقصة أو يوم غير صحيح')
            teacher_id = teachers.get(username)
            if not teacher_id:
                raise ValueError('رقم المعلمة غير موجود أو حسابها غير نشط')
            class_key = (cls, day, period)
            teacher_key = (teacher_id, day, period)
            if class_key in existing_class or class_key in occupied_class:
                raise ValueError('تعارض: الفصل لديه حصة في هذا الموعد')
            if teacher_key in existing_teacher or teacher_key in occupied_teacher:
                raise ValueError('تعارض: المعلمة لديها حصة في هذا الموعد')
            occupied_class.add(class_key)
            occupied_teacher.add(teacher_key)
            prepared.append((cls, day, period, subject, teacher_id))
        except ValueError as exc:
            errors.append(f'الصف {number}: {exc}')
    return prepared, errors


def import_timetable(rows, replace_existing=False):
    prepared, errors = validate_timetable(rows, replace_existing)
    if errors:
        return 0, errors
    try:
        with connect() as c:
            if replace_existing:
                c.execute('DELETE FROM timetable')
                c.execute('DELETE FROM teacher_classes')
            for cls, day, period, subject, teacher_id in prepared:
                c.execute('INSERT OR IGNORE INTO teacher_classes(teacher_id,class_name) VALUES(?,?)', (teacher_id, cls))
                c.execute('INSERT INTO timetable(class_name,day,period,subject,teacher_id) VALUES(?,?,?,?,?)',
                          (cls, day, period, subject, teacher_id))
        return len(prepared), []
    except sqlite3.IntegrityError:
        return 0, ['تغيّرت الجداول أثناء الاستيراد. أعيدي التحقق من التعارضات ثم ارفعي الملف مجددًا.']


def import_section(role):
    is_student = role == 'student'
    label = 'الطالبات' if is_student else 'المعلمات'
    columns = ['الرقم المدرسي', 'الاسم', 'الفصل'] if is_student else ['رقم المعلمة', 'الاسم']
    example = ['10001', 'سارة أحمد', 'أول ثانوي 1'] if is_student else ['T001', 'نورة محمد']
    st.download_button('تحميل نموذج '+label, xlsx_template(columns, example),
                       'students_template.xlsx' if is_student else 'teachers_template.xlsx',
                       mime='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    upload = st.file_uploader('رفع ملف '+label, type=['xlsx'], key='upload_'+role)
    if upload is None:
        return
    try:
        rows = read_sheet(upload, columns)
        accepted, errors = validate_people(rows, role)
        st.write(f'عدد الصفوف: {len(rows)}')
        st.dataframe(pd.DataFrame(rows[:10]), hide_index=True, width='stretch')
        if errors:
            st.error('صححي الأخطاء قبل الاستيراد: ' + ' | '.join(errors[:15]))
            return
        if st.button('إنشاء حسابات '+label, key='commit_'+role, disabled=not accepted):
            created, errors, skipped = import_people(rows, role)
            if errors:
                st.error(' | '.join(errors[:15]))
            else:
                st.session_state['credentials_'+role] = created
                st.success(f'تم إنشاء {len(created)} حساب، وتجاوز {skipped} رقم موجود مسبقًا.')
    except Exception as exc:
        st.error(f'تعذر قراءة ملف {label}: {exc}')
    credentials = st.session_state.get('credentials_'+role)
    if credentials:
        st.warning('ملف كلمات المرور حساس. نزّليه مرة واحدة ووزّعي البيانات لكل مستخدمة بشكل خاص، ثم امسحيه من الجهاز بعد التوزيع.')
        data = pd.DataFrame(credentials).to_csv(index=False).encode('utf-8-sig')
        st.download_button('تنزيل بيانات الدخول المؤقتة لـ'+label, data,
                           'temporary_'+role+'.csv', mime='text/csv', key='download_'+role)
        if st.button('إخفاء كلمات المرور من الشاشة', key='hide_'+role):
            st.session_state.pop('credentials_'+role, None)
            st.rerun()


def setup_timetable_import():
    columns = ['الفصل', 'اليوم', 'الحصة', 'المادة', 'رقم المعلمة']
    st.download_button('تحميل نموذج جدول الحصص', xlsx_template(columns, ['أول ثانوي 1', 'الأحد', 1, 'الرياضيات', 'T001']),
                       'timetable_template.xlsx', mime='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    upload = st.file_uploader('رفع جدول المدرسة', type=['xlsx'], key='setup_timetable_upload')
    if upload is None:
        return
    try:
        rows = read_sheet(upload, columns)
        st.write(f'عدد الحصص في الملف: {len(rows)}')
        st.dataframe(pd.DataFrame(rows[:12]), hide_index=True, width='stretch')
        replace_existing = st.checkbox('استبدال الجدول الدراسي الحالي بالكامل بالملف الجديد', value=True, help='يحذف الحصص القديمة فقط بعد التحقق من سلامة الملف الجديد، ولا يحذف حسابات الطالبات أو المعلمات.')
        prepared, errors = validate_timetable(rows, replace_existing)
        if errors:
            st.error(f'يوجد {len(errors)} خطأ أو تعارض. لم تُحفظ أي حصة.')
            st.dataframe(pd.DataFrame({'الخطأ': errors[:100]}), hide_index=True, width='stretch')
        elif not prepared:
            st.info('الملف لا يحتوي على حصص.')
        else:
            st.success(f'الجدول سليم: {len(prepared)} حصة بدون تعارض. سيتم ربط المعلمات بالفصول تلقائيًا.')
            if st.button('استبدال الجدول واعتماد الملف' if replace_existing else 'إضافة الحصص', key='commit_timetable'):
                count, issues = import_timetable(rows, replace_existing)
                if issues:
                    st.error(' | '.join(issues))
                else:
                    st.success(f'تم اعتماد {count} حصة.')
                    st.rerun()
    except Exception as exc:
        st.error(f'تعذر قراءة ملف الجدول: {exc}')


def school_setup():
    st.subheader('تهيئة المدرسة')
    st.write('ارفعي بيانات المدرسة بالترتيب. لا حاجة لإنشاء الحسابات أو الحصص واحدة واحدة.')
    counts = fetch("SELECT role,COUNT(*) n FROM users WHERE active=1 GROUP BY role")
    totals = {r['role']: r['n'] for r in counts}
    a, b, c = st.columns(3)
    a.metric('الطالبات', totals.get('student', 0))
    b.metric('المعلمات', totals.get('teacher', 0))
    c.metric('الحصص', fetch('SELECT COUNT(*) n FROM timetable')[0]['n'])
    t1, t2, t3, t4 = st.tabs(['1. الطالبات', '2. المعلمات', '3. الجدول الدراسي', '4. مراجعة البيانات'])
    with t1:
        import_section('student')
    with t2:
        import_section('teacher')
    with t3:
        st.info('كل يوم من الأحد إلى الخميس يحتوي على 7 حصص. إذا كان للمعلمة أو الفصل حصة في نفس الوقت، سيرفض النظام الملف قبل الحفظ.')
        setup_timetable_import()
    with t4:
        st.markdown('#### الفصول التي لم يكتمل جدولها')
        all_classes = classes()
        data = fetch('SELECT class_name,COUNT(*) n FROM timetable GROUP BY class_name')
        count_by_class = {r['class_name']: r['n'] for r in data}
        review = [{'الفصل': class_label(cls), 'الحصص المسجلة': count_by_class.get(cls, 0), 'المتبقي من 35': max(0, 35-count_by_class.get(cls, 0))} for cls in all_classes]
        if review:
            st.dataframe(pd.DataFrame(review), hide_index=True, width='stretch')
        else:
            st.info('لم تُضف فصول بعد.')
        st.markdown('#### الحسابات غير النشطة')
        inactive = fetch('SELECT username,full_name,role FROM users WHERE active=0')
        if inactive:
            st.dataframe(pd.DataFrame(inactive), hide_index=True, width='stretch')
        st.caption('تظهر المعلمات متفرغات حسب الحصص المسجلة فقط؛ أكْملي الجدول قبل الاعتماد على النتائج.')


def main():
    init()
    class_fix_error = normalize_school_classes()
    if class_fix_error:
        st.error(class_fix_error)
    st.markdown("""<style>
    html {lang: ar;}
    .stApp {direction: rtl;}
    [data-testid='stSidebar'] {direction: rtl;}
    [data-testid='stMarkdownContainer'] {unicode-bidi: plaintext;}
    body, [data-testid="stAppViewContainer"], [data-testid="stSidebar"] {font-family: 'Arial', 'Tahoma', sans-serif;}
    [data-testid="stMainBlockContainer"] {max-width: 1100px;}
    [data-testid="stMarkdownContainer"], [data-testid="stWidgetLabel"], [data-testid="stSidebar"] {direction: rtl; text-align: right;}
    [data-testid="stTextInput"] input, [data-testid="stTextArea"] textarea {direction: rtl; text-align: right;}
    h1, h2, h3, h4, p {overflow-wrap: anywhere;}
    [data-testid="stDataFrame"] {max-width: 100%; overflow-x: auto;}
    @media (max-width: 700px) {
        [data-testid="stMainBlockContainer"] {padding: 1.1rem .8rem 2rem !important;}
        h1 {font-size: 2rem !important; line-height: 1.4 !important;}
        h2 {font-size: 1.4rem !important;}
        [data-testid="stHorizontalBlock"] {flex-wrap: wrap; gap: .5rem;}
        [data-testid="stHorizontalBlock"] > div {min-width: 0 !important;}
        [data-testid="stSidebar"] {max-width: min(85vw, 300px);}
        button {min-height: 42px; white-space: normal !important;}
    }
    </style>""", unsafe_allow_html=True)
    try:
        import streamlit.components.v1 as components
        components.html("""<script>
        try {
          const d = window.parent.document;
          d.documentElement.lang = 'ar';
          d.documentElement.setAttribute('translate', 'no');
          if (!d.querySelector('meta[name="google"][content="notranslate"]')) {
            const m = d.createElement('meta'); m.name='google'; m.content='notranslate'; d.head.appendChild(m);
          }
        } catch(e) {}
        </script>""", height=0)
    except Exception:
        pass
    uid = st.session_state.get('user_id')
    user_rows = fetch('SELECT * FROM users WHERE id=? AND active=1', (uid,)) if uid else []
    if not user_rows:
        st.session_state.pop('user_id', None)
        login()
    else:
        user = user_rows[0]
        with st.sidebar:
            st.title('توازن')
            st.write(user['full_name'])
            role_label = {'admin': 'الإدارة', 'teacher': 'المعلمة', 'student': 'الطالبة'}[user['role']]
            st.caption(role_label)
            options = ['الرئيسية', 'جدول الحصص', 'الواجبات والاختبارات', 'إعدادات الحساب']
            if user['role'] == 'admin':
                options += ['تهيئة المدرسة', 'إدارة المستخدمين', 'إدارة الجداول', 'المعلمات المتفرغات', 'التقارير']
            page = st.radio('القائمة', options)
            if st.button('تغيير الدور / تسجيل الخروج'):
                st.session_state.clear()
                st.rerun()
        st.title('توازن')
        if user.get('must_change_password'):
            forced_password_change(user)
            st.markdown('---')
            st.markdown('<div style="text-align:center;color:#777;font-size:14px">إعداد الطالبة: لانا سلطان الشهري</div>',unsafe_allow_html=True)
            return
        if page == 'الرئيسية':
            st.subheader(f"مرحبًا، {user['full_name']}")
            if user['role'] == 'student':
                st.write(f"الفصل: {class_label(user['class_name'])}")
            elif user['role'] == 'teacher':
                st.write('فصولك: ' + ('، '.join(class_label(x) for x in allowed_classes(user)) or 'لم تحدد بعد'))
            else:
                c1, c2, c3 = st.columns(3)
                c1.metric('الطالبات', fetch('SELECT COUNT(*) n FROM users WHERE role="student"')[0]['n'])
                c2.metric('المعلمات', fetch('SELECT COUNT(*) n FROM users WHERE role="teacher"')[0]['n'])
                c3.metric('المهام', fetch('SELECT COUNT(*) n FROM tasks')[0]['n'])
            if user['role']=='admin':
                st.info('ابدئي من «تهيئة المدرسة» لرفع الطالبات والمعلمات والجداول دفعة واحدة، ثم راجعي المعلمات المتفرغات والتقارير.')
            elif user['role']=='teacher':
                teacher_dashboard(user)
            else:
                student_dashboard(user)
        elif page == 'جدول الحصص':
            show_timetable(user)
        elif page == 'إعدادات الحساب':
            account_settings(user)
        elif page == 'الواجبات والاختبارات':
            tasks_page(user)
            edit_tasks(user)
        elif page == 'تهيئة المدرسة' and user['role'] == 'admin':
            school_setup()
        elif page == 'إدارة المستخدمين' and user['role'] == 'admin':
            admin_users()
        elif page == 'إدارة الجداول' and user['role'] == 'admin':
            admin_timetable()
            edit_lessons()
            bulk_lessons()
        elif page == 'المعلمات المتفرغات' and user['role'] == 'admin':
            free_teachers()
        elif page == 'التقارير' and user['role'] == 'admin':
            reports()
    st.markdown('---')
    st.markdown('<div style="text-align:center; color:#777; font-size:14px">إعداد الطالبة: لانا سلطان الشهري</div>', unsafe_allow_html=True)

if __name__ == '__main__':
    main()
