#include<linux/linkage.h>

asmlinkage long sys_create_enclave(int i)
{
  return i+10;
}
