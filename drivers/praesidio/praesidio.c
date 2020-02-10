#include "praesidiodriver.h"
#include "praesidiosupervisor.h"

#include <linux/linkage.h>
#include <linux/dma-mapping.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kdev_t.h>
#include <linux/cdev.h>
#include <linux/fs.h>

//dma_alloc_coherent doc: https://lists.kernelnewbies.org/pipermail/kernelnewbies/2016-February/015687.html
//dma_alloc_coherent kernel doc: https://www.kernel.org/doc/Documentation/DMA-API-HOWTO.txt
//Tinsel example code: https://github.com/POETSII/tinsel/blob/master/hostlink/driver/dmabuffer.c
//Simple linux driver that doesn't automatically appear in /dev/: https://www.apriorit.com/dev-blog/195-simple-driver-for-linux-os
//How to get the above example to appear in /dev/: https://embetronicx.com/tutorials/linux/device-drivers/device-file-creation-for-character-drivers/
//Registering the fops and cdev to the device: https://embetronicx.com/tutorials/linux/device-drivers/cdev-structure-and-file-operations-of-character-drivers/

#define PAGE_SHIFT (12)

//Driver global variables
static dev_t praesidio_base_devnum = 0;
static const char praesidio_name[] = "praesidio-driver";
static struct class *praesidio_class = NULL;
struct cdev *praesidio_cdev = NULL;

//Driver function definitions
ssize_t praesidio_file_read (struct file *file_ptr, char *user_buffer, size_t count, loff_t *position);
static int praesidio_file_open (struct inode *inode, struct file *file);

static const struct file_operations praesidio_fops = {
  .owner          = THIS_MODULE,
  .open           = praesidio_file_open,
  // .ioctl          = praesidio_file_ioctly,
  // .mmap           = praesidio_file_mmap,
  .read           = praesidio_file_read,
};

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
  printk(KERN_NOTICE "sys_create_enclave: virtual address 0x%016lx and physical address 0x%016llx.\n", (unsigned long) cpu_addr, phys_addr);
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
asmlinkage unsigned long sys_create_send_mailbox(enclave_id_t receiver_id)
{
  dma_addr_t phys_addr = 0;
  void *cpu_addr = NULL;
  struct page *page = NULL;
  int status = 0;
  unsigned long ret_address = 0;
  cpu_addr = dma_alloc_coherent(
      NULL,
      1 << PAGE_SHIFT,
      &phys_addr, GFP_USER
  );
  printk(KERN_NOTICE "sys_create_send_mailbox: virtual address 0x%016lx and physical address 0x%016llx.\n", (unsigned long) cpu_addr, phys_addr);
  if (IS_ERR_OR_NULL(cpu_addr)) {
    printk(KERN_ERR "sys_create_send_mailbox: dma_alloc_coherent() failed\n");
    return 0;
  }

  // if(give_read_permission((void *) phys_addr, cpu_addr, receiver_id)) {
  //   printk(KERN_ERR "sys_create_send_mailbox: Failed to give read permission.\n");
  //   return 0;
  // }

  printk(KERN_NOTICE "translating address to page struct.\n");
  page = pfn_to_page(((phys_addr_t) phys_addr) >> PAGE_SHIFT); //pfn is physical address shifted to the right with page bit shift
  if(page == NULL) {
    printk(KERN_ERR "sys_create_send_mailbox: Failed to generate page struct from pfn.\n");
    return 0;
  }
  ret_address = current->mm->mmap->vm_start;
  printk(KERN_NOTICE "inserting page into virtual memory.\n");
  status = vm_insert_page(current->mm->mmap, ret_address, page);
  if(status) {
    printk(KERN_ERR "sys_create_send_mailbox: vm_insert_page failed with code %d.\n", status);
    return 0;
  }

  printk(KERN_NOTICE "returning now.\n");
  return ret_address;
}

asmlinkage unsigned long sys_get_receive_mailbox(enclave_id_t sender_id)
{
  struct page *page = NULL;
  volatile void *phys_addr = get_receive_mailbox_base_address(sender_id);
  unsigned long ret_address = 0;

  if(phys_addr == NULL) {
    printk(KERN_ERR "sys_get_receive_mailbox: Failed to get mailbox address from enclave.\n");
    return 0;
  }
  printk(KERN_NOTICE "sys_get_receive_mailbox: Getting receive mailbox with physicall address 0x%016lx\n", (unsigned long) phys_addr);

  page = pfn_to_page(((phys_addr_t) phys_addr) >> PAGE_SHIFT); //pfn is physical address shifted to the right with page bit shift
  if(page == NULL) {
    printk(KERN_ERR "sys_get_receive_mailbox: Failed to generate page struct from pfn.\n");
    return 0;
  }
  ret_address = current->mm->mmap->vm_start;
  if(vm_insert_page(current->mm->mmap, ret_address, page)) {
    printk(KERN_ERR "sys_get_receive_mailbox: Failed to map mailbox page into user space.\n");
    return 0;
  }

  return ret_address;
}

static const char    g_s_Hello_World_string[] = "Hello world from kernel mode!\n\0";
static const ssize_t g_s_Hello_World_size = sizeof(g_s_Hello_World_string);
ssize_t praesidio_file_read (struct file *file_ptr, char __user *user_buffer, size_t count, loff_t *position) {
  printk( KERN_NOTICE "Simple-driver: Device file is read at offset = %i, read bytes count = %u"
            , (int)*position
            , (unsigned int)count );
  /* If position is behind the end of a file we have nothing to read */
  if( *position >= g_s_Hello_World_size )
      return 0;
  /* If a user tries to read more than we have, read only as many bytes as we have */
  if( *position + count > g_s_Hello_World_size )
      count = g_s_Hello_World_size - *position;
  if( copy_to_user(user_buffer, g_s_Hello_World_string + *position, count) != 0 )
      return -EFAULT;
  /* Move reading position */
  *position += count;
  return count;
}

static void __exit praesidio_module_exit(void)
{
  printk(KERN_NOTICE "praesidio-driver: exiting module.\n");
  if(praesidio_class != NULL) {
    device_destroy(praesidio_class, praesidio_base_devnum);
    class_destroy(praesidio_class);
  }
  unregister_chrdev_region(praesidio_base_devnum, 1);
  if(praesidio_cdev != NULL) {
    cdev_del(praesidio_cdev);
  }
  return;
}

static int __init praesidio_module_init(void)
{
  int result;
  result = alloc_chrdev_region(&praesidio_base_devnum, 0, 1, "praesidio_dev");
  if(result < 0) {
    printk(KERN_ERR "praesidio_module_init: cannot allocate character device.\n");
    return result;
  }
  praesidio_class = class_create(THIS_MODULE, "praesidio_class");
  if(praesidio_class == NULL) {
    printk(KERN_ERR "praesidio_module_init: cannot create class.\n");
    return -1;
  }
  if(device_create(praesidio_class, NULL, praesidio_base_devnum, NULL, "praesidio") == NULL) {
    printk(KERN_ERR "praesidio_module_init: failed to create device.\n");
    unregister_chrdev_region(praesidio_base_devnum, 1);
    return -2;
  }
  praesidio_cdev = cdev_alloc();
  praesidio_cdev->ops = &praesidio_fops;
  result = cdev_add(praesidio_cdev, praesidio_base_devnum, 1);
  if (result < 0) {
    printk(KERN_ERR "praesidio_module_init: could not apply fops to device.\n");
    return result;
  }
  // result = register_chrdev(0, praesidio_name, &dmabuffer_fops);
  // if(result < 0) {
  //   printk(KERN_ERR "praesidio_module_init: failed to register module.\n");
  //   return result;
  // }
  printk(KERN_NOTICE "praesidio-driver: registered character device with major number %d and minor number %d.\n", MAJOR(praesidio_base_devnum), MINOR(praesidio_base_devnum));
  return 0;
}

static int praesidio_file_open (struct inode *inode, struct file *file) {
  printk(KERN_NOTICE "praesidio-driver: /dev/ file opened.\n");
  return 0;
}

module_init(praesidio_module_init);
module_exit(praesidio_module_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Marno van der Maas");
MODULE_DESCRIPTION("Driver to interface between user land and Praesidio enclaves.");
MODULE_VERSION("0.1");
