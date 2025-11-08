#include "password_lock.h"

#include <stdio.h>
#include <string.h>

/* 去掉 fgets 读取行尾的换行符，保持输入整洁 */
static void trim_newline(char *buffer) {
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n') {
        buffer[len - 1] = '\0';
    }
}

int main(void) {
    PasswordLock lock;
    char buffer[64];
    initializeLock(&lock);

    for (;;) {
        displayMenu();
        if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
            break;
        }
        trim_newline(buffer);
        int choice = buffer[0] - '0';
        switch (choice) {
            case 1: {
                if (lock.password[0] == '\0') {
                    printf("请先设置密码。\n\n");
                    continue;
                }
                printf("请输入密码: ");
                if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
                    break;
                }
                trim_newline(buffer);
                int result = unlock(&lock, buffer);
                if (result == 0) {
                    printf("开锁成功。\n");
                } else {
                    printf("密码错误，剩余次数: %d\n", lock.maxAttempts - lock.attemptCount);
                    if (lock.attemptCount >= lock.maxAttempts) {
                        printf("尝试次数已用尽，锁仍处于锁定状态。\n");
                    }
                }
                break;
            }
            case 2: {
                printf("输入新密码: ");
                if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
                    break;
                }
                trim_newline(buffer);
                if (setPassword(&lock, buffer) == 0) {
                    printf("密码设置成功。\n");
                } else {
                    printf("密码设置失败，内容不能为空。\n");
                }
                break;
            }
            case 3: {
                if (lock.isLocked) {
                    printf("请先开锁，再修改密码。\n");
                    break;
                }
                char oldPass[64];
                printf("输入旧密码: ");
                if (fgets(oldPass, sizeof(oldPass), stdin) == NULL) {
                    break;
                }
                trim_newline(oldPass);
                printf("输入新密码: ");
                if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
                    break;
                }
                trim_newline(buffer);
                int result = changePassword(&lock, oldPass, buffer);
                if (result == 0) {
                    printf("密码修改成功，锁已重新上锁。\n");
                } else if (result == -3) {
                    printf("旧密码错误。\n");
                } else if (result == -4) {
                    printf("新密码不能为空。\n");
                } else {
                    printf("密码修改失败。\n");
                }
                break;
            }
            case 4:
                resetLock(&lock);
                printf("锁已重置。\n");
                break;
            case 5:
                displayStatus(&lock);
                break;
            case 6:
                printf("退出程序。\n");
                return 0;
            default:
                printf("无效选择，请重新输入。\n");
                break;
        }
        printf("\n");
    }
    return 0;
}
