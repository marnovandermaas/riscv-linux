#include "praesidiodriver.h"
#include "praesidiosupervisor.h"

#include <linux/linkage.h>
#include <linux/dma-mapping.h>
#include <linux/string.h>
#include <linux/uaccess.h>

//dma_alloc_coherent doc: https://lists.kernelnewbies.org/pipermail/kernelnewbies/2016-February/015687.html
//dma_alloc_coherent kernel doc: https://www.kernel.org/doc/Documentation/DMA-API-HOWTO.txt
//Tinsel example code: https://github.com/POETSII/tinsel/blob/master/hostlink/driver/dmabuffer.c

#define PAGE_SHIFT (12)

asmlinkage enclave_id_t sys_create_enclave(void __user *enclave_memory)
{
  /*
  * Allocate enclave memory
  */
  dma_addr_t phys_addr = 0;
  size_t total_number_of_enclave_pages = 0;
  size_t i = 0;
  struct Message_t message;
  struct Message_t response;
  enclave_id_t currentEnclave, myEnclave;
  void *cpu_addr = NULL;
  unsigned long copy_status;
  total_number_of_enclave_pages = NUMBER_OF_ENCLAVE_PAGES+NUMBER_OF_COMMUNICATION_PAGES+NUMBER_OF_STACK_PAGES;
  cpu_addr = dma_alloc_coherent(
      NULL,
      (total_number_of_enclave_pages) << PAGE_SHIFT,
      &phys_addr, GFP_USER
  );
  printk("sys_create_enclave: virtual address 0x%016lx and physical address 0x%016llx.\n", (unsigned long) cpu_addr, phys_addr);
  if (IS_ERR_OR_NULL(cpu_addr)) {
    printk(KERN_ERR "sys_create_enclave: dma_alloc_coherent() failed\n");
    return -1;
  }

  //For reference: https://www.fsl.cs.sunysb.edu/kernel-api/re257.html
  copy_status = copy_from_user(cpu_addr, enclave_memory, NUMBER_OF_ENCLAVE_PAGES << PAGE_SHIFT); //Initialize enclave memory
  if (copy_status != 0) {
    printk(KERN_ERR "sys_create_enclave: Could not copy enclave memory from user space.\n");
    return -2;
  }

  /*
  * Create enclave context
  */
  currentEnclave = getCurrentEnclaveID();
  message.source = currentEnclave;
  message.destination = ENCLAVE_MANAGEMENT_ID;
  message.type = MSG_CREATE_ENCLAVE;
  message.content = 0;
  sendMessage(&message);
  do {
    receiveMessage(&response);
  } while(response.source != ENCLAVE_MANAGEMENT_ID);
  myEnclave = response.content;

  /*
  * Set enclave identifier argument for donate page message
  */
  message.type = MSG_SET_ARGUMENT;
  message.content = myEnclave;
  sendMessage(&message);
  do {
    receiveMessage(&response);
  } while(response.source != ENCLAVE_MANAGEMENT_ID);

  /*
  * Donate all allocated pages to enclave.
  */
  for(i = 0; i < total_number_of_enclave_pages; i++) {
    message.type = MSG_DONATE_PAGE;
    message.content = ((unsigned long) phys_addr) + (i << PAGE_SHIFT);
    sendMessage(&message);
    do {
      receiveMessage(&response);
    } while(response.source != ENCLAVE_MANAGEMENT_ID);
  }

  /*
  * Run enclave
  */
  message.type = MSG_SWITCH_ENCLAVE;
  message.content = myEnclave;
  sendMessage(&message);
  do {
    receiveMessage(&response);
  } while(response.source != ENCLAVE_MANAGEMENT_ID);

  return myEnclave; //Return enclave identifier to user
}

//reference: https://linux-kernel-labs.github.io/master/labs/memory_mapping.html
//reference: http://krishnamohanlinux.blogspot.com/2015/02/getuserpages-example.html
asmlinkage long sys_create_send_mailbox(const void __user *mailbox_root, enclave_id_t receiver_id)
{
  dma_addr_t phys_addr = 0;
  void *cpu_addr = NULL;
  struct page *page = NULL;
  int status = 0;
  cpu_addr = dma_alloc_coherent(
      NULL,
      1 << PAGE_SHIFT,
      &phys_addr, GFP_USER
  );
  printk("sys_create_send_mailbox: virtual address 0x%016lx and physical address 0x%016llx.\n", (unsigned long) cpu_addr, phys_addr);
  if (IS_ERR_OR_NULL(cpu_addr)) {
    printk(KERN_ERR "sys_create_send_mailbox: dma_alloc_coherent() failed\n");
    return -1;
  }

  if(give_read_permission((void *) phys_addr, cpu_addr, receiver_id)) {
    printk(KERN_ERR "sys_create_send_mailbox: Failed to give read permission.\n");
    return -2;
  }

  page = pfn_to_page(((phys_addr_t) phys_addr) >> PAGE_SHIFT); //pfn is physical address shifted to the right with page bit shift
  if(page == NULL) {
    printk(KERN_ERR "sys_create_send_mailbox: Failed to generate page struct from pfn.\n");
    return -3;
  }
  status = vm_insert_page(current->mm->mmap, (unsigned long) mailbox_root, page);
  if(status) {
    printk(KERN_ERR "sys_create_send_mailbox: vm_insert_page failed with code %d.\n", status);
    return -4;
  }

  return 0;
}

asmlinkage long sys_get_receive_mailbox(const void __user *mailbox_root, enclave_id_t sender_id)
{
  struct page *page;
  volatile void *phys_addr = get_receive_mailbox_base_address(sender_id);
  if(phys_addr == NULL) {
    printk(KERN_ERR "sys_get_receive_mailbox: Failed to get mailbox address from enclave.\n");
    return -1;
  }
  printk("sys_get_receive_mailbox: Getting receive mailbox with physicall address 0x%016lx\n", (unsigned long) phys_addr);

  page = pfn_to_page(((phys_addr_t) phys_addr) >> PAGE_SHIFT); //pfn is physical address shifted to the right with page bit shift
  if(page == NULL) {
    printk(KERN_ERR "sys_get_receive_mailbox: Failed to generate page struct from pfn.\n");
    return -2;
  }
  if(vm_insert_page(current->mm->mmap, (unsigned long) mailbox_root, page)) {
    printk(KERN_ERR "sys_get_receive_mailbox: Failed to map mailbox page into user space.\n");
    return -3;
  }
  return 0;
}
