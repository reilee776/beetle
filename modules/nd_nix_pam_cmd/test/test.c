#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CONFIG_FILE "settings.conf"

// 설정 파일에서 값을 읽는 함수
int read_config(const char *key, char *value, size_t value_size) {
    FILE *file = fopen(CONFIG_FILE, "r");
    if (file == NULL) {
        perror("Failed to open config file");
        return -1;
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        char *equals_sign = strchr(line, '=');
        if (equals_sign != NULL) {
            *equals_sign = '\0'; // Separate key and value
            if (strcmp(line, key) == 0) {
                strncpy(value, equals_sign + 1, value_size - 1);
                value[strcspn(value, "\n")] = '\0'; // Remove trailing newline
                fclose(file);
                return 0;
            }
        }
    }

    fclose(file);
    return -1; // Key not found
}

// 설정 파일에 값을 쓰는 함수
int write_config(const char *key, const char *value) {
    FILE *file = fopen(CONFIG_FILE, "r+");
    if (file == NULL) {
        perror("Failed to open config file");
        return -1;
    }

    char line[256];
    int found = 0;
    FILE *temp_file = fopen("temp.conf", "w");
    if (temp_file == NULL) {
        perror("Failed to open temporary file");
        fclose(file);
        return -1;
    }

    while (fgets(line, sizeof(line), file)) {
        char *equals_sign = strchr(line, '=');
        if (equals_sign != NULL) {
            *equals_sign = '\0'; // Separate key and value
            if (strcmp(line, key) == 0) {
                fprintf(temp_file, "%s=%s\n", key, value);
                found = 1;
            } else {
                fprintf(temp_file, "%s=%s", line, equals_sign + 1);
            }
        } else {
            fprintf(temp_file, "%s", line);
        }
    }

    if (!found) {
        fprintf(temp_file, "%s=%s\n", key, value);
    }

    fclose(file);
    fclose(temp_file);
    remove(CONFIG_FILE);
    rename("temp.conf", CONFIG_FILE);

    return 0;
}

// MODE 값을 변경하는 함수
void mode_change(int mode) {
    const char *value = (mode == 0) ? "OFF" : "ON";
    if (write_config("MODE", value) == 0) {
        printf("MODE set to %s\n", value);
    } else {
        printf("Failed to update MODE\n");
    }
}

// CONSOLE_MODE 값을 변경하는 함수
void console_mode_change(int mode) {
    const char *value = (mode == 0) ? "OFF" : "ON";
    if (write_config("CONSOLE_MODE", value) == 0) {
        printf("CONSOLE_MODE set to %s\n", value);
    } else {
        printf("Failed to update CONSOLE_MODE\n");
    }
}

int main() {
    // 파일에 현재 설정 읽기
    char value[10];
    if (read_config("MODE", value, sizeof(value)) == 0) {
        printf("Current MODE: %s\n", value);
    } else {
        printf("MODE not found\n");
    }

    if (read_config("CONSOLE_MODE", value, sizeof(value)) == 0) {
        printf("Current CONSOLE_MODE: %s\n", value);
    } else {
        printf("CONSOLE_MODE not found\n");
    }

    // MODE와 CONSOLE_MODE 변경 예시
    mode_change(1); // MODE를 ON으로 설정
    console_mode_change(0); // CONSOLE_MODE를 OFF로 설정

    return 0;
}

