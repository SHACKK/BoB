#include <stdio.h> // for printf
#include <stddef.h> // for size_t
#include <stdint.h> // for uint8_t
#include <netinet/in.h> // for use ntohs, htons ...

int main(int argc, char* argv[])
{
    char track[] = "개발";
    char name[] = "임창현";
    printf("------------------------------\n");
    printf("|[bob10][%s]add-nbo[%s]|\n", track, name);
    printf("------------------------------\n");

    //사용할 변수 선언
    uint32_t num1, num2, result;

    //thousand.bin파일 읽어와서 num1에 ntohl()함수 사용하여 저장
    FILE *thousand = fopen(argv[1], "r");
    fread(&num1, sizeof(num1), 1, thousand);
    num1 = ntohl(num1);

    //five-hundred.bin파일 읽어와서 num2에 ntohl()함수 사용하여 저장
    FILE *five_hundred = fopen(argv[2], "r");
    fread(&num2, sizeof(num2), 1, five_hundred);
    num2 = ntohl(num2);

    //num1과 num2의 값을 더하여 result에 저장, 각각을 출력해보고 최종 답안 출력
    result = num1+num2;
    printf("%s = 0x%08x\n", argv[1], num1);
    printf("%s = 0x%08x\n", argv[2], num2);
    printf("%d(0x%08x) + %d(0x%08x) = %d(0x%08x)\n", num1, num1, num2, num2, result, result);

    //파일 닫기
    if (fclose(thousand)| fclose(five_hundred))
        perror ("fclose error");
    else
        printf("closed file successfully..");

    return 0;
}
