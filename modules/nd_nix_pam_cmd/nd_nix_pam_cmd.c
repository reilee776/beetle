#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 파일에서 첫 번째 문자열을 검색하는 함수
int find_line_in_file(const char *filename, const char *key, char *found_line, size_t size) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        return -1; // 파일이 없거나 열 수 없음
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        char *delimiter = strchr(line, '|');
        if (delimiter != NULL) {
            *delimiter = '\0'; // 키와 값을 분리
            if (strcmp(line, key) == 0) {
                strncpy(found_line, line, size - 1);
                found_line[size - 1] = '\0';
                fclose(file);
                return 0; // 키가 발견됨
            }
        }
    }

    fclose(file);
    return 1; // 키가 발견되지 않음
}

// 파일의 모든 라인을 복사하여 새로운 파일에 작성하는 함수
int modify_file(const char *filename, const char *old_line, const char *new_line) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        return -1; // 파일이 없거나 열 수 없음
    }

    FILE *temp_file = fopen("temp.conf", "w");
    if (temp_file == NULL) {
        fclose(file);
        return -1; // 임시 파일을 열 수 없음
    }

    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, old_line, strlen(old_line)) == 0) {
            fprintf(temp_file, "%s\n", new_line);
            found = 1;
        } else {
            fprintf(temp_file, "%s", line);
        }
    }

    if (!found) {
        fprintf(temp_file, "%s\n", old_line);
    }

    fclose(file);
    fclose(temp_file);
    remove(filename);
    rename("temp.conf", filename);

    return 0;
}

// 파일에 문자열을 추가하는 함수
int append_to_file(const char *filename, const char *data) {
    FILE *file = fopen(filename, "a");
    if (file == NULL) {
        perror("Failed to open file");
        return -1;
    }

    fprintf(file, "%s\n", data);
    fclose(file);
    return 0;
}

// 파일에서 문자열을 삭제하는 함수
int delete_from_file(const char *filename, const char *key) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        return -1; // 파일이 없거나 열 수 없음
    }

    FILE *temp_file = fopen("temp.conf", "w");
    if (temp_file == NULL) {
        fclose(file);
        return -1; // 임시 파일을 열 수 없음
    }

    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), file)) {
        char *delimiter = strchr(line, '|');
        if (delimiter != NULL) {
            *delimiter = '\0'; // 키와 값을 분리
            if (strcmp(line, key) != 0) {
                fprintf(temp_file, "%s", line);
            } else {
                found = 1;
            }
        } else {
            fprintf(temp_file, "%s", line);
        }
    }

    fclose(file);
    fclose(temp_file);
    remove(filename);
    rename("temp.conf", filename);

    return found ? 0 : 1; // 삭제된 경우 0, 없던 경우 1
}

// 메인 함수
int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s rule <add|mod|del> <args...>\n", argv[0]);
        return 1;
    }

    const char *filename = "aaa.data";

    if (strcmp(argv[1], "rule") != 0) {
        fprintf(stderr, "Invalid rule parameter\n");
        return 1;
    }

    if (strcmp(argv[2], "add") == 0) {
        if (argc != 5) {
            fprintf(stderr, "Usage for add: %s rule add <field1> <field2> <field3>\n", argv[0]);
            return 1;
        }

        char data[256];
        snprintf(data, sizeof(data), "%s|%s|%s", argv[3], argv[4], argv[5]);

        if (find_line_in_file(filename, argv[3], NULL, 0) == 1) {
            if (append_to_file(filename, data) == 0) {
                printf("Data added successfully: %s\n", data);
            } else {
                printf("Failed to add data.\n");
            }
        } else {
            printf("The entry with the first field '%s' already exists.\n", argv[3]);
        }

    } else if (strcmp(argv[2], "mod") == 0) {
        if (argc != 5) {
            fprintf(stderr, "Usage for mod: %s rule mod <field1> <field2> <field3>\n", argv[0]);
            return 1;
        }

        char old_line[256];
        snprintf(old_line, sizeof(old_line), "%s|", argv[3]);

        char new_line[256];
        snprintf(new_line, sizeof(new_line), "%s|%s|%s", argv[3], argv[4], argv[5]);

        if (find_line_in_file(filename, argv[3], old_line, sizeof(old_line)) == 0) {
            if (modify_file(filename, old_line, new_line) == 0) {
                printf("Data modified successfully: %s\n", new_line);
            } else {
                printf("Failed to modify data.\n");
            }
        } else {
            printf("The entry with the first field '%s' does not exist.\n", argv[3]);
        }

    } else if (strcmp(argv[2], "del") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Usage for del: %s rule del <field1>\n", argv[0]);
            return 1;
        }

        if (delete_from_file(filename, argv[3]) == 0) {
            printf("Data deleted successfully.\n");
        } else {
            printf("Failed to delete data or entry does not exist.\n");
        }

    } else {
        fprintf(stderr, "Invalid command: %s\n", argv[2]);
        return 1;
    }

    return 0;
}

