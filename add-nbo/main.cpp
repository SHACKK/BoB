#include <stdio.h> // for printf
#include <stddef.h> // for size_t
#include <stdint.h> // for uint8_t
#include <netinet/in.h> // for use ntohs, htons ...

int main(int argc, char* argv[])
{
    printf("number of input file = %d\n", argc);
    printf("input file name is = %s, %s\n", argv[1], argv[2]);

    FILE* thousand = fopen(argv[1], "rb");
    FILE* five_hundred = fopen(argv[2], "rb");

    uint32_t num1 = fread(&num1, sizeof(thousand), 1, thousand);
    uint32_t num2 = fread(&num2, sizeof(five_hundred), 1, five_hundred);

    printf("num1 = 0x%x\n", num1);
    printf("num2 = 0x%x\n", num2);

    uint32_t result = ntohl(num1) + ntohl(num2);
    printf("===================================\n");
    printf("result = 0x%x\n", result);
    printf("===================================\n");
    printf("1000(0x3e8) + 500(0x1ft) = 1500(0x%x)", result);

    return 0;
}
