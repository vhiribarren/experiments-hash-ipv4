#ifndef uint32_t
#define uint32_t unsigned int
#endif

#define SHA256_PLAINTEXT_LENGTH		64
#define SHA256_BINARY_SIZE			32
#define SHA256_RESULT_SIZE			8

#define H0 0x6a09e667
#define H1 0xbb67ae85
#define H2 0x3c6ef372
#define H3 0xa54ff53a
#define H4 0x510e527f
#define H5 0x9b05688c
#define H6 0x1f83d9ab
#define H7 0x5be0cd19

int build_ipv4_address(uint32_t ip, char * result);
bool is_equal(uint size, uint * first, uint * second);
void swap(char *xp, char *yp);
void reverse(char str[], int length);
uint itoa(int num, char * str, int base);
uint rotr(uint x, int n);
uint ch(uint x, uint y, uint z);
uint maj(uint x, uint y, uint z);
uint sigma0(uint x);
uint sigma1(uint x);
uint gamma0(uint x);
uint gamma1(uint x);
void sha256_crypt(uint data_len, char *plain_key,  uint *digest);

void swap(char *xp, char *yp) 
{ 
    char temp = *xp; 
    *xp = *yp; 
    *yp = temp; 
} 

void reverse(char str[], int length) 
{ 
    int start = 0; 
    int end = length -1; 
    while (start < end) 
    { 
        swap((str+start), (str+end)); 
        start++; 
        end--; 
    } 
} 

// Implementation of itoa() 
uint itoa(int num, char* str, int base) 
{ 
    int i = 0; 
    bool isNegative = false; 
  
    /* Handle 0 explicitely, otherwise empty string is printed for 0 */
    if (num == 0) 
    { 
        str[i++] = '0'; 
        str[i] = '\0'; 
        return i; 
    } 
  
    // In standard itoa(), negative numbers are handled only with  
    // base 10. Otherwise numbers are considered unsigned. 
    if (num < 0 && base == 10) 
    { 
        isNegative = true; 
        num = -num; 
    } 
  
    // Process individual digits 
    while (num != 0) 
    { 
        int rem = num % base; 
        str[i++] = (rem > 9)? (rem-10) + 'a' : rem + '0'; 
        num = num/base; 
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


int build_ipv4_address(uint32_t ip, char * result) {
    // Result buffer must be minimum of size 16
    uint ip_parts[4] = {0};
    ip_parts[0] = (ip & 0xFF000000) >> 24;
    ip_parts[1] = (ip & 0x00FF0000) >> 16;
    ip_parts[2] = (ip & 0x0000FF00) >> 8;
    ip_parts[3] = (ip & 0x000000FF) >> 0;
    uint pos = 0;
    for (int i=0; i<4; i++) {
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

uint rotr(uint x, int n) {
  if (n < 32) return (x >> n) | (x << (32 - n));
  return x;
}

uint ch(uint x, uint y, uint z) {
  return (x & y) ^ (~x & z);
}

uint maj(uint x, uint y, uint z) {
  return (x & y) ^ (x & z) ^ (y & z);
}

uint sigma0(uint x) {
  return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

uint sigma1(uint x) {
  return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

uint gamma0(uint x) {
  return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

uint gamma1(uint x) {
  return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

// From https://github.com/Fruneng/opencl_sha_al_im
void sha256_crypt(uint data_len, char *plain_key,  uint *digest){
  int t;
  int stop, mmod;
  uint i, ulen, item, total, msg_pad;
  uint W[80], A,B,C,D,E,F,G,H,T1,T2;
  int current_pad;

  uint K[64]={
0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

  msg_pad=0;

  ulen = data_len;
  total = ulen%64>=56?2:1 + ulen/64;

//  printf("ulen: %u total:%u\n", ulen, total);

  digest[0] = H0;
  digest[1] = H1;
  digest[2] = H2;
  digest[3] = H3;
  digest[4] = H4;
  digest[5] = H5;
  digest[6] = H6;
  digest[7] = H7;
  for(item=0; item<total; item++)
  {

    A = digest[0];
    B = digest[1];
    C = digest[2];
    D = digest[3];
    E = digest[4];
    F = digest[5];
    G = digest[6];
    H = digest[7];

#pragma unroll
    for (t = 0; t < 80; t++){
    W[t] = 0x00000000;
    }
    msg_pad=item*64;
    if(ulen > msg_pad)
    {
      current_pad = (ulen-msg_pad)>64?64:(ulen-msg_pad);
    }
    else
    {
      current_pad =-1;    
    }

  //  printf("current_pad: %d\n",current_pad);
    if(current_pad>0)
    {
      i=current_pad;

      stop =  i/4;
  //    printf("i:%d, stop: %d msg_pad:%d\n",i,stop, msg_pad);
      for (t = 0 ; t < stop ; t++){
        W[t] = ((uchar)  plain_key[msg_pad + t * 4]) << 24;
        W[t] |= ((uchar) plain_key[msg_pad + t * 4 + 1]) << 16;
        W[t] |= ((uchar) plain_key[msg_pad + t * 4 + 2]) << 8;
        W[t] |= (uchar)  plain_key[msg_pad + t * 4 + 3];
        //printf("W[%u]: %u\n",t,W[t]);
      }
      mmod = i % 4;
      if ( mmod == 3){
        W[t] = ((uchar)  plain_key[msg_pad + t * 4]) << 24;
        W[t] |= ((uchar) plain_key[msg_pad + t * 4 + 1]) << 16;
        W[t] |= ((uchar) plain_key[msg_pad + t * 4 + 2]) << 8;
        W[t] |=  ((uchar) 0x80) ;
      } else if (mmod == 2) {
        W[t] = ((uchar)  plain_key[msg_pad + t * 4]) << 24;
        W[t] |= ((uchar) plain_key[msg_pad + t * 4 + 1]) << 16;
        W[t] |=  0x8000 ;
      } else if (mmod == 1) {
        W[t] = ((uchar)  plain_key[msg_pad + t * 4]) << 24;
        W[t] |=  0x800000 ;
      } else /*if (mmod == 0)*/ {
        W[t] =  0x80000000 ;
      }
      
      if (current_pad<56)
      {
        W[15] =  ulen*8 ;
        //printf("ulen avlue 2 :w[15] :%u\n", W[15]);
      }
    }
    else if(current_pad <0)
    {
      if( ulen%64==0)
        W[0]=0x80000000;
      W[15]=ulen*8;
      //printf("ulen avlue 3 :w[15] :%u\n", W[15]);
    }

    for (t = 0; t < 64; t++) {
      if (t >= 16)
        W[t] = gamma1(W[t - 2]) + W[t - 7] + gamma0(W[t - 15]) + W[t - 16];
      T1 = H + sigma1(E) + ch(E, F, G) + K[t] + W[t];
      T2 = sigma0(A) + maj(A, B, C);
      H = G; G = F; F = E; E = D + T1; D = C; C = B; B = A; A = T1 + T2;
    }
    digest[0] += A;
    digest[1] += B;
    digest[2] += C;
    digest[3] += D;
    digest[4] += E;
    digest[5] += F;
    digest[6] += G;
    digest[7] += H;

  //  for (t = 0; t < 80; t++)
  //    {
  //    printf("W[%d]: %u\n",t,W[t]);
  //    }
  }


}

bool is_equal(uint size, uint * first, uint * second) {
  	for(uint i=0; i<size; i++)
	{
		if (first[i] != second[i]) {
            return false;
        }
	}
    return true;
}


__kernel void ipv4_hash(__global float *res_g) { 
    uint binary_result[SHA256_RESULT_SIZE];
    //uint sample_result[] = {0x19e36255, 0x972107d4, 0x2b8cecb7, 0x7ef5622e, 0x842e8a50, 0x778a6ed8, 0xdd1ce947, 0x32daca9e};
    uint sample_result[6][8] = {
      {0x19e36255, 0x972107d4, 0x2b8cecb7, 0x7ef5622e, 0x842e8a50, 0x778a6ed8, 0xdd1ce947, 0x32daca9e},   // 0.0.0.0
      {0x52ab14a4, 0x8cb94196, 0x3a498fae, 0xfd02b109, 0x0ebfccfe, 0x47f07d54, 0x52628d82, 0x80b60154},   // 1.0.0.0
      {0x12ca17b4, 0x9af22894, 0x36f303e0, 0x166030a2, 0x1e525d26, 0x6e209267, 0x433801a8, 0xfd4071a0},   // 127.0.0.1
      {0x37d7a806, 0x04871e57, 0x9850a658, 0xc7add2ae, 0x7557d0c6, 0xabcc9b31, 0xecddc442, 0x4207eba3},   // 192.168.0.1
      {0xc4249e36, 0x619119f4, 0xcaee1035, 0xf63e28b8, 0x0809a6e7, 0x643feb27, 0x305a84b0, 0x129a12d0},   // 254.0.0.1
      {0xf45462bf, 0x3cd12ea2, 0xb347f32f, 0x6c4d0a0d, 0x36e01694, 0xde332b30, 0x7af90d42, 0x951c5bd6},   // 255.255.255.255
    };

    int gid = get_global_id(0);
    char  ip_string[16];
    int len = build_ipv4_address(gid, ip_string);
    sha256_crypt(len, ip_string, binary_result);

  for (int sample=0; sample < 6; sample++) {
    if (is_equal(SHA256_RESULT_SIZE, binary_result, sample_result[sample])) {
        for(int i=0; i<SHA256_RESULT_SIZE; i++)
        {
          printf("%08x", binary_result[i]);
        }
        printf("\n");
        break;
    }
  }



/*
	for(int i=0; i<SHA256_RESULT_SIZE; i++)
	{
		printf("%08x", binary_result[i]);
	}
    printf("\n");
*/
    //int gid = get_global_id(0);

    //res_g[gid] = 10 * gid;
}