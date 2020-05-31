#include "sha256.cl"

int build_ipv4_address(uint32_t ip, char *result);
bool is_equal(uint size, uint *first, __constant uint *second);
void swap(char *xp, char *yp);
void reverse(char str[], int length);
uint itoa(int num, char *str, int base);

bool is_equal(uint size, uint *first, __constant uint *second) {
  for (uint i = 0; i < size; i++) {
    if (first[i] != second[i]) {
      return false;
    }
  }
  return true;
}

void swap(char *xp, char *yp) {
  char temp = *xp;
  *xp = *yp;
  *yp = temp;
}

void reverse(char str[], int length) {
  int start = 0;
  int end = length - 1;
  while (start < end) {
    swap((str + start), (str + end));
    start++;
    end--;
  }
}

uint itoa(int num, char *str, int base) {
  int i = 0;
  bool isNegative = false;

  /* Handle 0 explicitely, otherwise empty string is printed for 0 */
  if (num == 0) {
    str[i++] = '0';
    str[i] = '\0';
    return i;
  }

  // In standard itoa(), negative numbers are handled only with
  // base 10. Otherwise numbers are considered unsigned.
  if (num < 0 && base == 10) {
    isNegative = true;
    num = -num;
  }

  // Process individual digits
  // VH C'est cette boucle qui semble poser soucis
  while (num != 0) {
    int rem = num % base;
    str[i++] = (rem > 9) ? (rem - 10) + 'a' : rem + '0';
    num = num / base;
  }

  // If number is negative, append '-'
  if (isNegative)
    str[i++] = '-';

  str[i] = '\0'; // Append string terminator
                 // printf("%s\n", str);
  // Reverse the string

  reverse(str, i);

  return i;
}

int build_ipv4_address(uint32_t ip, char *result) {
  // Result buffer must be minimum of size 16
  uint32_t ip_parts[4] = {0};
  ip_parts[0] = (ip & 0xFF000000) >> 24;
  ip_parts[1] = (ip & 0x00FF0000) >> 16;
  ip_parts[2] = (ip & 0x0000FF00) >> 8;
  ip_parts[3] = (ip & 0x000000FF) >> 0;
  uint pos = 0;
  for (int i = 0; i < 4; i++) {
    uint len = itoa(ip_parts[i], result + pos, 10);
    pos += len;
    if (i != 3) {
      result[pos] = '.';
      pos++;
    }
  }
  result[pos] = '\0';
  return pos;
}

    __constant  uint sample_result[6][8] = {
        {0x19e36255, 0x972107d4, 0x2b8cecb7, 0x7ef5622e, 0x842e8a50, 0x778a6ed8, 0xdd1ce947, 0x32daca9e}, // 0.0.0.0
        {0x52ab14a4, 0x8cb94196, 0x3a498fae, 0xfd02b109, 0x0ebfccfe, 0x47f07d54, 0x52628d82, 0x80b60154}, // 1.0.0.0
        {0x12ca17b4, 0x9af22894, 0x36f303e0, 0x166030a2, 0x1e525d26, 0x6e209267, 0x433801a8, 0xfd4071a0}, // 127.0.0.1
        {0x37d7a806, 0x04871e57, 0x9850a658, 0xc7add2ae, 0x7557d0c6, 0xabcc9b31, 0xecddc442, 0x4207eba3}, // 192.168.0.1
        {0xc4249e36, 0x619119f4, 0xcaee1035, 0xf63e28b8, 0x0809a6e7, 0x643feb27, 0x305a84b0, 0x129a12d0}, // 254.0.0.1
        {0xf45462bf, 0x3cd12ea2, 0xb347f32f, 0x6c4d0a0d, 0x36e01694, 0xde332b30, 0x7af90d42, 0x951c5bd6}, // 255.255.255.255
    };


__kernel void ipv4_hash(const uint32_t iter_per_workitem, __global const uint32_t *targets_buf,  __global uint32_t * success_buf, __global uint32_t * results_buf) {



    uint32_t base_task_id = get_global_id(0) * iter_per_workitem;

    char ip_string[16] = {0};
    uint binary_result[SHA256_RESULT_SIZE] = {0};

    for (uint iter=0; iter < iter_per_workitem; iter++) {
        uint32_t task_id=base_task_id+iter;
        int addr_str_len = build_ipv4_address(task_id, ip_string);
        sha256_crypt(addr_str_len, ip_string, binary_result);

        for (int sample=0; sample < 6; sample++) {

            if (is_equal(SHA256_RESULT_SIZE, binary_result, sample_result[sample])) {
                success_buf[sample]=1;
                results_buf[sample]=task_id;
                break;
            }
        }
        
    }


}