-- CyberPhishGuard Quiz Data Viewer
-- Use this in SQLTools to view quiz results

-- View all quiz results
SELECT 
    id,
    user_id,
    score,
    total_questions,
    percentage,
    timestamp,
    wrong_questions,
    full_answers
FROM myapp_quizlog 
ORDER BY timestamp DESC 
LIMIT 20;

-- View quiz results with usernames
SELECT 
    ql.id,
    u.username,
    u.email,
    ql.score,
    ql.total_questions,
    ql.percentage,
    ql.timestamp,
    JSON_LENGTH(ql.wrong_questions) as wrong_count,
    JSON_LENGTH(ql.full_answers) as answered_count
FROM myapp_quizlog ql
LEFT JOIN auth_user u ON ql.user_id = u.id
ORDER BY ql.timestamp DESC;

-- View quiz statistics
SELECT 
    COUNT(*) as total_quizzes,
    AVG(score) as avg_score,
    AVG(percentage) as avg_percentage,
    COUNT(CASE WHEN score = total_questions THEN 1 END) as perfect_scores,
    COUNT(CASE WHEN score >= 7 THEN 1 END) as good_scores,
    COUNT(CASE WHEN score < 5 THEN 1 END) as poor_scores
FROM myapp_quizlog;

-- View quiz results by user
SELECT 
    u.username,
    COUNT(*) as total_quizzes,
    AVG(ql.score) as avg_score,
    MAX(ql.percentage) as best_percentage,
    MIN(ql.timestamp) as first_quiz,
    MAX(ql.timestamp) as last_quiz
FROM myapp_quizlog ql
JOIN auth_user u ON ql.user_id = u.id
GROUP BY u.username
ORDER BY avg_score DESC;

-- View detailed quiz breakdown for latest quiz
SELECT 
    ql.id,
    u.username,
    ql.score,
    ql.total_questions,
    ql.percentage,
    ql.timestamp,
    ql.wrong_questions,
    ql.full_answers
FROM myapp_quizlog ql
LEFT JOIN auth_user u ON ql.user_id = u.id
ORDER BY ql.timestamp DESC 
LIMIT 1;