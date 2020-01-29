#include <linux/linkage.h>
#include <linux/dma-mapping.h>
#include "praesidio.h"
#include "instructions.h"
#include <string.h>
#include <linux/uaccess.h>

//dma_alloc_coherent doc: https://lists.kernelnewbies.org/pipermail/kernelnewbies/2016-February/015687.html
//dma_alloc_coherent kernel doc: https://www.kernel.org/doc/Documentation/DMA-API-HOWTO.txt
//Tinsel example code: https://github.com/POETSII/tinsel/blob/master/hostlink/driver/dmabuffer.c

#define PAGE_SHIFT (12)

asmlinkage unsigned long sys_create_enclave(void __user *enclave_memory)
{
  /*
  * Allocate enclave memory
  */
  dma_addr_t phys_addr;
  size_t total_number_of_enclave_pages = NUMBER_OF_ENCLAVE_PAGES+NUMBER_OF_COMMUNICATION_PAGES+NUMBER_OF_STACK_PAGES;
  void *cpu_addr = dma_alloc_coherent(
      NULL,
      (total_number_of_enclave_pages) << PAGE_SHIFT,
      &phys_addr, GFP_KERNEL
  );
  //printk("virtual address 0x%016p and physical address 0x%016llx.\n", cpu_addr, phys_addr);
  if (IS_ERR_OR_NULL(cpu_addr)) {
    printk(KERN_ERR "dma_alloc_coherent() failed\n");
    return -1;
  }

  copy_from_user(cpu_addr, enclave_memory, NUMBER_OF_ENCLAVE_PAGES << PAGE_SHIFT); //Initialize enclave memory

  /*
  * Create enclave context
  */
  struct Message_t message;
  struct Message_t response;
  enclave_id_t currentEnclave = getCurrentEnclaveID();
  message.source = currentEnclave;
  message.destination = ENCLAVE_MANAGEMENT_ID;
  message.type = MSG_CREATE_ENCLAVE;
  message.content = 0;
  sendMessage(&message);
  do {
    receiveMessage(&response);
  } while(response.source != ENCLAVE_MANAGEMENT_ID);
  enclave_id_t myEnclave = response.content;

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
  for(size_t i = 0; i < total_number_of_enclave_pages; i++) {
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

asmlinkage void* sys_create_send_mailbox(unsigned long receiver_id)
{
  return NULL; //TODO
}

asmlinkage volatile void* sys_get_receive_mailbox(unsigned long sender_id)
{
  return NULL; //TODO
}
