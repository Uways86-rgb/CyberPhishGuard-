-- CyberPhishGuard Complete Database Viewer
-- Use this in SQLTools to view all data

-- ========================================
-- 1. USER DATA
-- ========================================
SELECT 
    id,
    username,
    email,
    first_name,
    last_name,
    is_staff,
    is_superuser,
    is_active,
    date_joined,
    last_login
FROM auth_user 
ORDER BY date_joined DESC;

-- ========================================
-- 2. QUIZ LOG DATA
-- ========================================
SELECT 
    ql.id,
    u.username,
    ql.score,
    ql.total_questions,
    ql.percentage,
    ql.timestamp,
    JSON_LENGTH(ql.wrong_questions) as wrong_count,
    JSON_LENGTH(ql.full_answers) as answered_count
FROM myapp_quizlog ql
LEFT JOIN auth_user u ON ql.user_id = u.id
ORDER BY ql.timestamp DESC;

-- ========================================
-- 3. SCAN LOG DATA
-- ========================================
SELECT 
    sl.id,
    sl.scan_type,
    sl.target,
    sl.result,
    sl.scan_time,
    u.username,
    sl.duration
FROM myapp_scanlog sl
LEFT JOIN auth_user u ON sl.user_id = u.id
ORDER BY sl.scan_time DESC;

-- ========================================
-- 4. THREAT LOG DATA
-- ========================================
SELECT 
    tl.id,
    tl.threat_type,
    tl.severity,
    tl.status,
    tl.source_ip,
    tl.target_ip,
    tl.url,
    tl.file_hash,
    tl.description,
    tl.detection_method,
    tl.confidence_score,
    tl.timestamp,
    u.username
FROM myapp_threatlog tl
LEFT JOIN auth_user u ON tl.reported_by_id = u.id
ORDER BY tl.timestamp DESC;

-- ========================================
-- 5. LOGIN LOG DATA
-- ========================================
SELECT 
    ll.id,
    u.username,
    ll.login_time,
    ll.ip_address,
    ll.session_id,
    ll.status
FROM myapp_loginlog ll
LEFT JOIN auth_user u ON ll.user_id = u.id
ORDER BY ll.login_time DESC;

-- ========================================
-- 6. LOGOUT LOG DATA
-- ========================================
SELECT 
    ol.id,
    u.username,
    ol.logout_time,
    ol.ip_address,
    ol.session_id,
    ol.status
FROM myapp_logoutlog ol
LEFT JOIN auth_user u ON ol.user_id = u.id
ORDER BY ol.logout_time DESC;

-- ========================================
-- 7. THREAT INTELLIGENCE DATA
-- ========================================
SELECT 
    ti.id,
    ti.indicator_type,
    ti.indicator_value,
    ti.threat_type,
    ti.severity,
    ti.description,
    ti.source,
    ti.is_active,
    ti.created_at,
    ti.updated_at
FROM myapp_threatintelligence ti
ORDER BY ti.created_at DESC;

-- ========================================
-- 8. COMBINED STATISTICS
-- ========================================
SELECT 
    'Users' as category,
    COUNT(*) as count
FROM auth_user
    
UNION ALL

SELECT 
    'Quiz Results' as category,
    COUNT(*) as count
FROM myapp_quizlog

UNION ALL

SELECT 
    'Scan Logs' as category,
    COUNT(*) as count
FROM myapp_scanlog

UNION ALL

SELECT 
    'Threat Logs' as category,
    COUNT(*) as count
FROM myapp_threatlog

UNION ALL

SELECT 
    'Login Logs' as category,
    COUNT(*) as count
FROM myapp_loginlog

UNION ALL

SELECT 
    'Logout Logs' as category,
    COUNT(*) as count
FROM myapp_logoutlog

UNION ALL

SELECT 
    'Threat Intelligence' as category,
    COUNT(*) as count
FROM myapp_threatintelligence;

-- ========================================
-- 9. RECENT ACTIVITY SUMMARY
-- ========================================
SELECT 
    'Latest Quiz' as activity,
    MAX(timestamp) as last_activity
FROM myapp_quizlog

UNION ALL

SELECT 
    'Latest Scan' as activity,
    MAX(scan_time) as last_activity
FROM myapp_scanlog

UNION ALL

SELECT 
    'Latest Threat' as activity,
    MAX(timestamp) as last_activity
FROM myapp_threatlog

UNION ALL

SELECT 
    'Latest Login' as activity,
    MAX(login_time) as last_activity
FROM myapp_loginlog

UNION ALL

SELECT 
    'Latest Logout' as activity,
    MAX(logout_time) as last_activity
FROM myapp_logoutlog

UNION ALL

SELECT 
    'Latest Threat Intel' as activity,
    MAX(created_at) as last_activity
FROM myapp_threatintelligence;