#include <mysql.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>

// PAM 대화 구조체
static struct pam_conv conv = {
    NULL, NULL
};

// 사용자 인증 함수
int pam_authenticate_user(const char *username, const char *password, const char *ip_address) {
    pam_handle_t *pamh = NULL;
    int retval;

    // PAM 초기화
    retval = pam_start("mariadb", username, &conv, &pamh);
    if (retval != PAM_SUCCESS) {
        return 0; // 초기화 실패
    }

    // 비밀번호 설정
    retval = pam_set_item(pamh, PAM_AUTHTOK, password);
    if (retval != PAM_SUCCESS) {
        pam_end(pamh, retval);
        return 0; // 비밀번호 설정 실패
    }

    // 인증 수행
    retval = pam_authenticate(pamh, 0);
    
    // 인증 결과에 따라 IP와 계정 정보 출력
    if (retval == PAM_SUCCESS) {
        printf("Authentication successful for user: %s from IP: %s\n", username, ip_address);
    } else {
        printf("Authentication failed for user: %s from IP: %s\n", username, ip_address);
    }

    pam_end(pamh, retval); // PAM 세션 종료

    return (retval == PAM_SUCCESS) ? 1 : 0; // 인증 성공 여부 반환
}

// MariaDB 플러그인 초기화
my_bool pam_auth_plugin_init(void) {
    return 0; // 초기화 성공
}

// MariaDB 플러그인 종료
my_bool pam_auth_plugin_deinit(void) {
    return 0; // 종료 성공
}

// MariaDB에서 호출되는 인증 함수
int pam_authenticate_mariadb(MYSQL *conn, const char *user, const char *password, const char *ip_address) {
    return pam_authenticate_user(user, password, ip_address);
}

// 플러그인 버전 정의
MYSQL_PLUGIN_PLUGIN_VERSION MYSQL_VERSION_ID;

