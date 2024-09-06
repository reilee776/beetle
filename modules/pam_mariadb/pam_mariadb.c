#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <mysql.h>

static struct pam_conv conv = {
    NULL, NULL
};

// 사용자 인증 함수
int pam_authenticate_user(const char *username, const char *password) {
    MYSQL *conn;
    MYSQL_RES *res;
    MYSQL_ROW row;
    char query[256];

    // MariaDB에 연결
    conn = mysql_init(NULL);
    if (conn == NULL) {
        return 0; // 연결 초기화 실패
    }

    if (mysql_real_connect(conn, "localhost", "myuser", "mypassword", "mydatabase", 0, NULL, 0) == NULL) {
        mysql_close(conn);
        return 0; // 연결 실패
    }

    // SQL 쿼리 실행
    snprintf(query, sizeof(query), "SELECT username FROM users WHERE username='%s' AND password='%s'", username, password);
    if (mysql_query(conn, query)) {
        mysql_close(conn);
        return 0; // 쿼리 실패
    }

    res = mysql_store_result(conn);
    if (res == NULL) {
        mysql_close(conn);
        return 0; // 결과 저장 실패
    }

    int valid = (mysql_num_rows(res) > 0);
    mysql_free_result(res);
    mysql_close(conn);

    return valid; // 인증 결과 반환
}

// PAM 인증 함수
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *username;
    char password[256]; // 비밀번호를 저장할 배열
    int retval;

    // 사용자 이름 가져오기
    retval = pam_get_user(pamh, &username, NULL);
    if (retval != PAM_SUCCESS) return retval;

    // 비밀번호 입력 요청
    printf("Password: ");
    if (fgets(password, sizeof(password), stdin) == NULL) {
        return PAM_BUF_ERR; // 입력 오류
    }
    password[strcspn(password, "\n")] = 0; // 개행 문자 제거

    // 사용자 인증
    if (!pam_authenticate_user(username, password)) {
        return PAM_AUTH_ERR; // 인증 실패
    }

    return PAM_SUCCESS; // 인증 성공
}

