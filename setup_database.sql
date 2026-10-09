-- ==========================================
-- 1. สร้างตารางและฟังก์ชันพื้นฐาน
-- ==========================================
CREATE TABLE teachers (
    user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE students (
    id VARCHAR(11) PRIMARY KEY,
    title VARCHAR(20),
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    section VARCHAR(10),
    user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    photo_path TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    kind VARCHAR(4) CHECK (kind IN ('pre', 'post')),
    score INTEGER NOT NULL,
    answers JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, kind)
);

CREATE TABLE progress (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    unit INTEGER NOT NULL,
    done BOOLEAN DEFAULT FALSE,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, unit)
);

CREATE TABLE submissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    unit INTEGER NOT NULL,
    kind VARCHAR(10) CHECK (kind IN ('link', 'file')),
    url TEXT,
    storage_path TEXT,
    note TEXT,
    score NUMERIC(5,2) DEFAULT NULL,
    teacher_comment TEXT DEFAULT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE materials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title TEXT NOT NULL,
    kind VARCHAR(10) CHECK (kind IN ('file', 'link', 'video')),
    url TEXT,
    storage_path TEXT,
    file_name TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ==========================================
-- 2. ฟังก์ชันตรวจสอบสิทธิ์ (Security Definer)
-- ==========================================
CREATE OR REPLACE FUNCTION public.is_teacher()
RETURNS BOOLEAN AS $$
BEGIN
  RETURN EXISTS (SELECT 1 FROM public.teachers WHERE user_id = auth.uid());
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

-- ==========================================
-- 3. Row Level Security (RLS)
-- ==========================================
ALTER TABLE teachers ENABLE ROW LEVEL SECURITY;
ALTER TABLE students ENABLE ROW LEVEL SECURITY;
ALTER TABLE attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE progress ENABLE ROW LEVEL SECURITY;
ALTER TABLE submissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE materials ENABLE ROW LEVEL SECURITY;

-- Revoke anon
REVOKE ALL ON teachers, students, attempts, progress, submissions, materials FROM anon;

-- Policies: Teachers
CREATE POLICY "Teacher full access to teachers" ON teachers FOR ALL TO authenticated USING (is_teacher());

-- Policies: Students (Table)
CREATE POLICY "Teacher read all students" ON students FOR SELECT TO authenticated USING (is_teacher());
CREATE POLICY "Student read own profile" ON students FOR SELECT TO authenticated USING (user_id = auth.uid());
CREATE POLICY "Student update own photo" ON students FOR UPDATE TO authenticated USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

-- Policies: Attempts
CREATE POLICY "Teacher read all attempts" ON attempts FOR SELECT TO authenticated USING (is_teacher());
CREATE POLICY "Student read own attempts" ON attempts FOR SELECT TO authenticated USING (user_id = auth.uid());
CREATE POLICY "Student insert own attempts" ON attempts FOR INSERT TO authenticated WITH CHECK (user_id = auth.uid());

-- Policies: Progress
CREATE POLICY "Teacher read all progress" ON progress FOR SELECT TO authenticated USING (is_teacher());
CREATE POLICY "Student manage own progress" ON progress FOR ALL TO authenticated USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

-- Policies: Submissions
CREATE POLICY "Teacher manage all submissions" ON submissions FOR ALL TO authenticated USING (is_teacher());
CREATE POLICY "Student read own submissions" ON submissions FOR SELECT TO authenticated USING (user_id = auth.uid());
CREATE POLICY "Student insert own submissions" ON submissions FOR INSERT TO authenticated WITH CHECK (user_id = auth.uid());
CREATE POLICY "Student update own submissions" ON submissions FOR UPDATE TO authenticated USING (user_id = auth.uid()); 
-- (การป้องกันการแก้คะแนนถูกจัดการด้วย Trigger ด้านล่าง)

-- Policies: Materials
CREATE POLICY "All authenticated read materials" ON materials FOR SELECT TO authenticated USING (true);
CREATE POLICY "Teacher manage materials" ON materials FOR ALL TO authenticated USING (is_teacher());

-- ==========================================
-- 4. Trigger ป้องกันผู้เรียนแก้คะแนนและข้อเสนอแนะ
-- ==========================================
CREATE OR REPLACE FUNCTION prevent_student_score_update()
RETURNS trigger AS $$
BEGIN
    IF NOT public.is_teacher() THEN
        IF (NEW.score IS DISTINCT FROM OLD.score) OR (NEW.teacher_comment IS DISTINCT FROM OLD.teacher_comment) THEN
            RAISE EXCEPTION 'นักศึกษาไม่อนุญาตให้แก้ไขคะแนนหรือข้อเสนอแนะของผู้สอน';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER check_submission_update
BEFORE UPDATE ON submissions
FOR EACH ROW
EXECUTE FUNCTION prevent_student_score_update();

-- ==========================================
-- 5. Trigger ผูกบัญชีผู้เรียนอัตโนมัติ
-- ==========================================
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger AS $$
DECLARE
  v_student_id text;
BEGIN
  -- ตรวจสอบว่าเป็นรูปแบบอีเมลนักศึกษาหรือไม่ (ขึ้นต้นด้วยตัวเลข 11 หลัก)
  IF NEW.email ~ '^[0-9]{11}@' THEN
    v_student_id := split_part(NEW.email, '@', 1);
    
    -- ตรวจสอบว่ามีรายชื่อในระบบหรือไม่
    IF NOT EXISTS (SELECT 1 FROM public.students WHERE id = v_student_id) THEN
      RAISE EXCEPTION 'รหัสนักศึกษานี้ไม่มีในระบบ หรือไม่ได้รับอนุญาตให้ลงทะเบียน';
    END IF;
    
    -- ตรวจสอบว่าถูกใช้ไปแล้วหรือไม่
    IF EXISTS (SELECT 1 FROM public.students WHERE id = v_student_id AND user_id IS NOT NULL) THEN
      RAISE EXCEPTION 'รหัสนักศึกษานี้ถูกลงทะเบียนไปแล้ว';
    END IF;
    
    -- ผูก UUID กับนักศึกษา
    UPDATE public.students SET user_id = NEW.id WHERE id = v_student_id;
  END IF;
  -- หากไม่ใช่อีเมลนักศึกษา (เช่น ผู้สอน) จะข้ามการตรวจสอบและสมัครได้ปกติ
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER on_auth_user_created
AFTER INSERT ON auth.users
FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- ==========================================
-- 6. มุมมอง Results (Security Invoker = true)
-- ==========================================
CREATE VIEW results WITH (security_invoker = true) AS
SELECT 
    s.id AS student_id,
    s.title, s.first_name, s.last_name, s.section,
    pre.score AS pre_score,
    post.score AS post_score,
    CASE 
        WHEN pre.score = 10 THEN 0 -- จัดการกรณีคะแนนเต็มเพื่อป้องกันหารด้วยศูนย์ (0/0)
        WHEN post.score IS NOT NULL AND pre.score IS NOT NULL 
        THEN (post.score::numeric - pre.score::numeric) / (10.0 - pre.score::numeric)
        ELSE NULL 
    END AS normalized_gain
FROM students s
LEFT JOIN attempts pre ON s.user_id = pre.user_id AND pre.kind = 'pre'
LEFT JOIN attempts post ON s.user_id = post.user_id AND post.kind = 'post';

-- ==========================================
-- 7. ตั้งค่า Storage Buckets & Policies
-- ==========================================
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES 
  ('photos', 'photos', false, 2097152, ARRAY['image/png', 'image/jpeg']), -- 2MB
  ('submissions', 'submissions', false, 20971520, ARRAY['image/png', 'image/jpeg', 'application/pdf', 'video/mp4']), -- 20MB
  ('materials', 'materials', false, 52428800, ARRAY['application/pdf', 'application/vnd.openxmlformats-officedocument.presentationml.presentation', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']) -- 50MB
ON CONFLICT (id) DO NOTHING;

-- Storage RLS
-- photos: นร. อัปโหลด/ดู ได้เฉพาะโฟลเดอร์ UID ตัวเอง, ครูดูได้หมด
CREATE POLICY "Student manage own photo" ON storage.objects FOR ALL TO authenticated USING (bucket_id = 'photos' AND (storage.foldername(name))[1] = auth.uid()::text) WITH CHECK (bucket_id = 'photos' AND (storage.foldername(name))[1] = auth.uid()::text);
CREATE POLICY "Teacher read all photos" ON storage.objects FOR SELECT TO authenticated USING (bucket_id = 'photos' AND public.is_teacher());

-- submissions: เหมือน photos
CREATE POLICY "Student manage own submissions" ON storage.objects FOR ALL TO authenticated USING (bucket_id = 'submissions' AND (storage.foldername(name))[1] = auth.uid()::text) WITH CHECK (bucket_id = 'submissions' AND (storage.foldername(name))[1] = auth.uid()::text);
CREATE POLICY "Teacher read all submissions" ON storage.objects FOR SELECT TO authenticated USING (bucket_id = 'submissions' AND public.is_teacher());

-- materials: ทุกคนอ่านได้, ครูจัดการได้
CREATE POLICY "All read materials" ON storage.objects FOR SELECT TO authenticated USING (bucket_id = 'materials');
CREATE POLICY "Teacher manage materials" ON storage.objects FOR ALL TO authenticated USING (bucket_id = 'materials' AND public.is_teacher());

-- ==========================================
-- 8. ข้อมูลจำลอง (Dummy Data) 6 แถว
-- ==========================================
-- วิธีนำเข้ารายชื่อจริง: 
-- 1. ไปที่ Supabase Studio -> Table Editor -> เลือกตาราง students
-- 2. เลือก Insert -> Import data from CSV 
-- 3. อัปโหลดไฟล์ CSV ที่มีคอลัมน์ id, title, first_name, last_name, section (ห้ามมีคอลัมน์ user_id)
INSERT INTO students (id, title, first_name, last_name, section) VALUES
('66123456701', 'นาย', 'สมชาย', 'เรียนดี', '01'),
('66123456702', 'นางสาว', 'สมหญิง', 'ขยันยิ่ง', '01'),
('66123456703', 'นาย', 'มานะ', 'อดทน', '02'),
('66123456704', 'นางสาว', 'มานี', 'มีใจ', '02'),
('66123456705', 'นาย', 'ปิติ', 'ยินดี', '03'),
('66123456706', 'นางสาว', 'ชูใจ', 'ใฝ่รู้', '03');

-- ==========================================
-- 9. คำสั่งตั้งผู้สอน (ลบ -- เพื่อใช้งาน)
-- ==========================================
-- INSERT INTO auth.users (id, email) VALUES (gen_random_uuid(), 'teacher@snru.ac.th'); -- สร้างผู้ใช้
-- INSERT INTO teachers (user_id) VALUES ((SELECT id FROM auth.users WHERE email = 'teacher@snru.ac.th'));