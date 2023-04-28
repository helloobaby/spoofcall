/*

jmp_rbx_0 shellcode -> _spoofer_stub.fixup -> test_function -> _spoofer_stub -> MessageBoxA -> jmp_rbx_0 shellcode

*/


#include <iostream>
#include <windows.h>
#include "spoofcall.h"
using namespace std;


#pragma section(".text")
__declspec(allocate(".text")) const unsigned char jmp_rbx_0[] = {0xff, 0x23};//jmp qword ptr[rbx]

int test_function(int k, float p) {
  int pp = p;
  return k + pp;
}


int main() {
  const auto ret = spoof_call(jmp_rbx_0, &test_function, 1, 2.0f);
  printf("%d\n", ret);

  spoof_call(jmp_rbx_0,&MessageBoxA,(HWND)0,(LPCSTR)"hello",(LPCSTR)"info",(UINT)MB_OK);

  //spoof_call(jmp_rbx_0, &CreateFileA, "test.txt", GENERIC_READ | GENERIC_WRITE,FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL, NULL);

  spoof_call(jmp_rbx_0, &CreateFileA, (LPCSTR)"test.txt", (DWORD)(GENERIC_READ | GENERIC_WRITE),(DWORD)(FILE_SHARE_WRITE | FILE_SHARE_READ), (LPSECURITY_ATTRIBUTES)NULL, (DWORD)CREATE_ALWAYS,(DWORD)FILE_ATTRIBUTE_NORMAL, (HANDLE)NULL);

  return 0;
}
