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
  dma_addr_t phys_addr;
  size_t total_number_of_enclave_pages;
  size_t i;
  struct Message_t message;
  struct Message_t response;
  enclave_id_t currentEnclave, myEnclave;
  void *cpu_addr;
  unsigned long copy_status;
  //printk("syscall create enclave is called.\n");
  total_number_of_enclave_pages = NUMBER_OF_ENCLAVE_PAGES+NUMBER_OF_COMMUNICATION_PAGES+NUMBER_OF_STACK_PAGES;
  cpu_addr = dma_alloc_coherent(
      NULL,
      (total_number_of_enclave_pages) << PAGE_SHIFT,
      &phys_addr, GFP_KERNEL
  );
  //printk("virtual address 0x%016p and physical address 0x%016llx.\n", cpu_addr, phys_addr);
  if (IS_ERR_OR_NULL(cpu_addr)) {
    printk(KERN_ERR "dma_alloc_coherent() failed\n");
    return -1;
  }

  //For reference: https://www.fsl.cs.sunysb.edu/kernel-api/re257.html
  copy_status = copy_from_user(cpu_addr, enclave_memory, NUMBER_OF_ENCLAVE_PAGES << PAGE_SHIFT); //Initialize enclave memory
  if (copy_status != 0) {
    printk(KERN_ERR "Could not copy enclave memory from user space.\n");
    return -1;
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

asmlinkage void __user *sys_create_send_mailbox(enclave_id_t receiver_id)
{
  dma_addr_t phys_addr;
  void *cpu_addr;
  cpu_addr = dma_alloc_coherent(
      NULL,
      1 << PAGE_SHIFT,
      &phys_addr, GFP_KERNEL
  );
  if(give_read_permission(phys_addr, receiver_id)) {
    printk(KERN_ERR "Failed to give read permission.\n");
    return NULL;
  }
  //TODO map phys_addr into userspace
  return NULL; //TODO return userspace pointer
}

asmlinkage volatile void __user *sys_get_receive_mailbox(enclave_id_t sender_id)
{
  void *phys_addr = get_receive_mailbox_base_address(sender_id);
  //TODO map phys_addr into userspace
  return NULL; //TODO userspace pointer
}
