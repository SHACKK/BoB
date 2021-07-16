#include <stdio.h> // for printf
#include <stddef.h> // for size_t
#include <stdint.h> // for uint8_t
#include <netinet/in.h> // for use ntohs, htons ...

int main(int argc, char* argv[])
{
    printf("----------------------\n");
    printf("|LIM CHANG HYEON_MADE|\n");
    printf("----------------------\n");
    uint32_t num1, num2, result;

    FILE *thousand = fopen(argv[1], "r");
    fread(&num1, sizeof(num1), 1, thousand);
    num1 = ntohl(num1);

    FILE *five_hundred = fopen(argv[2], "r");
    fread(&num2, sizeof(num2), 1, five_hundred);
    num2 = ntohl(num2);

    result = num1+num2;
    printf("%s = 0x%08x\n", argv[1], num1);
    printf("%s = 0x%08x\n", argv[2], num2);

    printf("%d(0x%08x) + %d(0x%08x) = %d(0x%08x)\n", num1, num1, num2, num2, result, result);

    if (fclose(thousand)| fclose(five_hundred))
        perror ("fclose error");
    else
        printf("closed file successfully..");

    return 0;
}
