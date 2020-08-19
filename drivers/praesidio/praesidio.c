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
#include <linux/slab.h>

//dma_alloc_coherent doc: https://lists.kernelnewbies.org/pipermail/kernelnewbies/2016-February/015687.html
//dma_alloc_coherent kernel doc: https://www.kernel.org/doc/Documentation/DMA-API-HOWTO.txt
//Tinsel example code: https://github.com/POETSII/tinsel/blob/master/hostlink/driver/dmabuffer.c
//Simple linux driver that doesn't automatically appear in /dev/: https://www.apriorit.com/dev-blog/195-simple-driver-for-linux-os
//How to get the above example to appear in /dev/: https://embetronicx.com/tutorials/linux/device-drivers/device-file-creation-for-character-drivers/
//Registering the fops and cdev to the device: https://embetronicx.com/tutorials/linux/device-drivers/cdev-structure-and-file-operations-of-character-drivers/

//Source: https://embetronicx.com/tutorials/linux/device-drivers/ioctl-tutorial-in-linux/

#define MAXIMUM_AMOUNT_OF_ENCLAVES (256)

//Driver global variables
static dev_t praesidio_base_devnum = 0;
static const char praesidio_name[] = "praesidio-driver";
static struct class *praesidio_class = NULL;
struct cdev *praesidio_cdev = NULL;
struct cdev *praesidio_enclave_cdev = NULL;

//Driver function definitions
ssize_t praesidio_file_read (struct file *file_ptr, char *user_buffer, size_t count, loff_t *position);
static long praesidio_file_ioctl (struct file *file_ptr, unsigned int ioctl_num, unsigned long ioctl_param);
static long praesidio_enclave_ioctl (struct file *file_ptr, unsigned int ioctl_num, unsigned long ioctl_param);
static int praesidio_enclave_mmap (struct file *file_ptr, struct vm_area_struct *vma);

static const struct file_operations praesidio_fops = {
  .owner          = THIS_MODULE,
  .unlocked_ioctl = praesidio_file_ioctl,
  //.read           = praesidio_file_read,
};

static const struct file_operations praesidio_enclave_fops = {
  .owner          = THIS_MODULE,
  .unlocked_ioctl = praesidio_enclave_ioctl,
  .mmap           = praesidio_enclave_mmap,
};

enum praesidio_ioctl_state_t {
  praesidio_ioctl_none,
  praesidio_ioctl_create_enclave,
  praesidio_ioctl_create_send_mailbox,
  praesidio_ioctl_get_receive_mailbox,
};

struct praesidio_enclave_private_data_t {
  enclave_id_t enclave_identifier;// = ENCLAVE_INVALID_ID;
  int process_identifier; //use task_pid_nr(current) to get the pid of the calling user process
  unsigned long tx_page;// = 0;
  unsigned long rx_page;// = 0;
  enum praesidio_ioctl_state_t ioctl_operation;// = praesidio_ioctl_none;
};

asmlinkage enclave_id_t __create_enclave(void __user *enclave_memory)
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
  int label = 100;
  int label2 = 200;
  total_number_of_enclave_pages = NUMBER_OF_ENCLAVE_PAGES+NUMBER_OF_COMMUNICATION_PAGES+NUMBER_OF_STACK_PAGES;
  OUTPUT_STATS(label2+1);
  OUTPUT_STATS(label2);
  cpu_addr = dma_alloc_coherent(
      NULL,
      (total_number_of_enclave_pages) << PAGE_BIT_SHIFT,
      &phys_addr, GFP_USER
  );
  OUTPUT_STATS(label2);
#ifdef PRAESIDIO_DEBUG
  printk(KERN_NOTICE "sys_create_enclave: virtual address 0x%016lx and physical address 0x%016llx.\n", (unsigned long) cpu_addr, phys_addr);
#endif
  if (IS_ERR_OR_NULL(cpu_addr)) {
    printk(KERN_ERR "sys_create_enclave: dma_alloc_coherent() failed\n");
    return ENCLAVE_INVALID_ID;
  }

  OUTPUT_STATS(label2);
  //For reference: https://www.fsl.cs.sunysb.edu/kernel-api/re257.html
  copy_status = copy_from_user(cpu_addr, enclave_memory, NUMBER_OF_ENCLAVE_PAGES << PAGE_BIT_SHIFT); //Initialize enclave memory
  OUTPUT_STATS(label2);
  if (copy_status != 0) {
    printk(KERN_ERR "sys_create_enclave: Could not copy enclave memory from user space.\n");
    return ENCLAVE_INVALID_ID;
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
  OUTPUT_STATS(label);
  do {
    receiveMessage(&response);
  } while(response.source != ENCLAVE_MANAGEMENT_ID);
  OUTPUT_STATS(label);
  myEnclave = response.content;

  /*
  * Set enclave identifier argument for donate page message
  */
  message.type = MSG_SET_ARGUMENT;
  message.content = myEnclave;
  sendMessage(&message);
  OUTPUT_STATS(label);
  do {
    receiveMessage(&response);
  } while(response.source != ENCLAVE_MANAGEMENT_ID);
  OUTPUT_STATS(label);

  /*
  * Donate all allocated pages to enclave.
  */
  for(i = 0; i < total_number_of_enclave_pages; i++) {
    message.type = MSG_DONATE_PAGE;
    message.content = ((unsigned long) phys_addr) + (i << PAGE_BIT_SHIFT);
    sendMessage(&message);
    OUTPUT_STATS(label+i+1);
    do {
      receiveMessage(&response);
    } while(response.source != ENCLAVE_MANAGEMENT_ID);
    OUTPUT_STATS(label+i+1);
  }

  /*
  * Finalize enclave
  */
  message.type = MSG_FINALIZE;
  message.content = myEnclave;
  sendMessage(&message);
  OUTPUT_STATS(label);
  do {
    receiveMessage(&response);
  } while(response.source != ENCLAVE_MANAGEMENT_ID);
  OUTPUT_STATS(label);

  /*
  * Run enclave
  */
  message.type = MSG_SWITCH_ENCLAVE;
  message.content = myEnclave;
  sendMessage(&message);
  OUTPUT_STATS(label);
  do {
    receiveMessage(&response);
  } while(response.source != ENCLAVE_MANAGEMENT_ID);
  OUTPUT_STATS(label);

  OUTPUT_STATS(label2+1);
  return myEnclave; //Return enclave identifier to user
}

//reference: https://linux-kernel-labs.github.io/master/labs/memory_mapping.html
//reference: http://krishnamohanlinux.blogspot.com/2015/02/getuserpages-example.html
int __create_send_mailbox(struct file *file_ptr, struct vm_area_struct *vma)
{
  dma_addr_t phys_addr = 0;
  void *cpu_addr = NULL;
  struct page *page = NULL;
  struct praesidio_enclave_private_data_t *enclave_data = (struct praesidio_enclave_private_data_t *) file_ptr->private_data;
  int status = 0;
  cpu_addr = dma_alloc_coherent(
      NULL,
      1 << PAGE_BIT_SHIFT,
      &phys_addr, GFP_KERNEL
  );
#ifdef PRAESIDIO_DEBUG
  printk(KERN_NOTICE "__create_send_mailbox: virtual address 0x%016lx and physical address 0x%016llx.\n", (unsigned long) cpu_addr, phys_addr);
#endif
  if (IS_ERR_OR_NULL(cpu_addr)) {
    printk(KERN_ERR "__create_send_mailbox: dma_alloc_coherent() failed\n");
    return -1;
  }

  if(give_read_permission((void *) phys_addr, cpu_addr, enclave_data->enclave_identifier)) {
    printk(KERN_ERR "sys_create_send_mailbox: Failed to give read permission.\n");
    return -1;
  }

  page = pfn_to_page(((phys_addr_t) phys_addr) >> PAGE_BIT_SHIFT); //pfn is physical address shifted to the right with page bit shift
  if(page == NULL) {
    printk(KERN_ERR "__create_send_mailbox: Failed to generate page struct from pfn.\n");
    return -1;
  }
  status = vm_insert_page(vma, vma->vm_start, page);
  if(status) {
    printk(KERN_ERR "__create_send_mailbox: vm_insert_page failed with code %d.\n", status);
    return -1;
  }

  return 0;
}

int __get_receive_mailbox(struct file *file_ptr, struct vm_area_struct *vma)
{
  struct page *page = NULL;
  struct praesidio_enclave_private_data_t *enclave_data = (struct praesidio_enclave_private_data_t *) file_ptr->private_data;
  volatile void *phys_addr;
  int status = 0;

  phys_addr = get_read_only_page(enclave_data->enclave_identifier);

  if(phys_addr == NULL) {
    printk(KERN_ERR "__get_receive_mailbox: Failed to get mailbox address from enclave.\n");
    return -1;
  }
#ifdef PRAESIDIO_DEBUG
  printk(KERN_NOTICE "__get_receive_mailbox: Getting receive mailbox with physical address 0x%016lx\n", (unsigned long) phys_addr);
#endif

  page = pfn_to_page(((phys_addr_t) phys_addr) >> PAGE_BIT_SHIFT); //pfn is physical address shifted to the right with page bit shift
  if(page == NULL) {
    printk(KERN_ERR "__get_receive_mailbox: Failed to generate page struct from pfn.\n");
    return -1;
  }
  if(!page_count(page)) {
#ifdef PRAESIDIO_DEBUG
    printk(KERN_NOTICE "__get_receive_mailbox: overwriting page count to 1.\n");
#endif
    set_page_count(page, 1); //TODO is this allowed?
  }

  status = vm_insert_page(vma, vma->vm_start, page);
  if(status) {
    printk(KERN_ERR "__get_receive_mailbox: Failed to map mailbox page into user space, with code %d\n", status);
    return -1;
  }

  return 0;
}

#define ENCLAVE_DEVICE_NAME_MAX_CHAR (128)
static int internal_enclave_count = 1;

static long praesidio_file_ioctl (struct file *file_ptr, unsigned int ioctl_num, unsigned long ioctl_param) {
  int result;
  dev_t enclave_device_number = MKDEV(MAJOR(praesidio_base_devnum), internal_enclave_count);
  char enclave_name[ENCLAVE_DEVICE_NAME_MAX_CHAR];
  void __user *user_buffer = (void __user *) ioctl_param;
  if(internal_enclave_count > MAXIMUM_AMOUNT_OF_ENCLAVES) {
    printk(KERN_ERR "praesidio_file_ioctl: cannot create more than %d enclave.\n", MAXIMUM_AMOUNT_OF_ENCLAVES);
    return -1;
  }
  sprintf(enclave_name, "praesidio%d", internal_enclave_count);
  internal_enclave_count += 1;
  if(device_create(praesidio_class, NULL, enclave_device_number, NULL, enclave_name) == NULL) {
    printk(KERN_ERR "praesidio_file_ioctl: failed to create enclave device.\n");
    return -2;
  }
  result = cdev_add(praesidio_enclave_cdev, enclave_device_number, 1);
  if (result < 0) {
    printk(KERN_ERR "praesidio_file_ioctl: could not apply fops to enclave device.\n");
    return result;
  }

#ifdef PRAESIDIO_DEBUG
  printk(KERN_NOTICE "praesidio-driver: registered character device with major number %d and minor number %d on /dev/%s.\n", MAJOR(enclave_device_number), MINOR(enclave_device_number), enclave_name);
#endif
  if(copy_to_user(user_buffer, enclave_name, strnlen(enclave_name, ENCLAVE_DEVICE_NAME_MAX_CHAR-1)+1)) {
    printk(KERN_ERR "praesidio-driver: could not copy device name to user space.\n");
    return -3;
  }
  return 0;
}

static long praesidio_enclave_ioctl (struct file *file_ptr, unsigned int cmd, unsigned long ioctl_param) {
  struct praesidio_enclave_private_data_t *current_record = NULL;
  enclave_id_t enclave_id = ENCLAVE_INVALID_ID;
#ifdef PRAESIDIO_DEBUG
  printk(KERN_NOTICE "praesidio_enclave_ioctl: called ioctl with num %u and param %lu.\n", cmd, ioctl_param);
#endif
  enclave_id_t currentEnclave = ENCLAVE_INVALID_ID;
  struct Message_t message, response;
  struct praesidio_enclave_private_data_t *enclave_data;
  switch(cmd) {
    case IOCTL_CREATE_ENCLAVE:
      if(file_ptr->private_data != NULL) {
        printk(KERN_NOTICE "praesidio-driver: cannot create enclave because there already is one.\n");
        return -1;
      }
#ifdef PRAESIDIO_DEBUG
      printk(KERN_NOTICE "praesidio-driver: requestion create enclave.\n");
#endif
      current_record = (struct praesidio_enclave_private_data_t *) kmalloc(sizeof(struct praesidio_enclave_private_data_t), GFP_KERNEL);
      enclave_id = __create_enclave((void __user *) ioctl_param);
#ifdef PRAESIDIO_DEBUG
      printk(KERN_NOTICE "praesidio-driver: created enclave %llu\n", enclave_id);
#endif
      if(enclave_id != ENCLAVE_INVALID_ID) {
        current_record->enclave_identifier = enclave_id;
        current_record->process_identifier = task_pid_nr(current);
        current_record->tx_page = 0;
        current_record->rx_page = 0;
        current_record->ioctl_operation = praesidio_ioctl_none;
        file_ptr->private_data = current_record;
      } else {
        printk(KERN_ERR "praesidio-driver: Failed to create enclave.\n");
      }
      //TODO return enclave_id
      return 0;
    case IOCTL_CREATE_SEND_MAILBOX:
#ifdef PRAESIDIO_DEBUG
      printk(KERN_NOTICE "praesidio-driver: setting ioctl operation to send mailbox.\n");
#endif
      current_record = (struct praesidio_enclave_private_data_t *) file_ptr->private_data;
      current_record->ioctl_operation = praesidio_ioctl_create_send_mailbox;
      return 0;
    case IOCTL_GET_RECEIVE_MAILBOX:
      current_record = (struct praesidio_enclave_private_data_t *) file_ptr->private_data;
      current_record->ioctl_operation = praesidio_ioctl_get_receive_mailbox;
      return 0;
    case IOCTL_ATTEST_ENCLAVE:
        currentEnclave = getCurrentEnclaveID();
        message.source = currentEnclave;
        message.destination = ENCLAVE_MANAGEMENT_ID;
        message.type = MSG_SET_ARGUMENT;
        message.content = ioctl_param >> 32; //32-bit enclave identifier encoded in most significant bits
        sendMessage(&message);
        do {
          receiveMessage(&response);
        } while(response.source != ENCLAVE_MANAGEMENT_ID);
        message.type = MSG_ATTEST;
        message.content = ioctl_param & 0xFFFFFFFF; //32-bit nonce encoded in least significant bits
        sendMessage(&message);
        do {
          receiveMessage(&response);
        } while(response.source != ENCLAVE_MANAGEMENT_ID);
        //TODO return attestation result to enclave.
        return 0;
    case IOCTL_DELETE_ENCLAVE:
      enclave_data = (struct praesidio_enclave_private_data_t *) file_ptr->private_data;
      currentEnclave = getCurrentEnclaveID();
      message.source = currentEnclave;
      message.destination = ENCLAVE_MANAGEMENT_ID;
      message.type = MSG_DELETE_ENCLAVE;
      message.content = enclave_data->enclave_identifier; //identifier of enclave to be deleted
      sendMessage(&message);
      do {
        receiveMessage(&response);
      } while(response.source != ENCLAVE_MANAGEMENT_ID);
      //TODO delete character device
      return 0;
    default:
      printk(KERN_ERR "praesidio-driver: unsupported ioctl cmd %u.\n", cmd);
      return -1;
  }
}
static int praesidio_enclave_mmap (struct file *file_ptr, struct vm_area_struct *vma) {
  //TODO make this dependent on ioctl_op
  struct praesidio_enclave_private_data_t *current_record = (struct praesidio_enclave_private_data_t *) file_ptr->private_data;
  if(current_record == NULL) {
    printk(KERN_NOTICE "praesidio-driver: must create enclave before mmaping.\n");
    return -1;
  }
  switch(current_record->ioctl_operation) {
    case praesidio_ioctl_create_send_mailbox:
      current_record->ioctl_operation = praesidio_ioctl_none;
      return __create_send_mailbox(file_ptr, vma);
    case praesidio_ioctl_get_receive_mailbox:
      current_record->ioctl_operation = praesidio_ioctl_none;
      return __get_receive_mailbox(file_ptr, vma);
    default:
      printk(KERN_NOTICE "praesidio-driver: must ask for send or receive mailbox before calling mmap.\n");
      return -1;
  }
}

static void __exit praesidio_module_exit(void)
{
#ifdef PRAESIDIO_DEBUG
  printk(KERN_NOTICE "praesidio-driver: exiting module.\n");
#endif
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
  result = alloc_chrdev_region(&praesidio_base_devnum, 0, MAXIMUM_AMOUNT_OF_ENCLAVES, "praesidio_dev");
  if(result < 0) {
    printk(KERN_ERR "praesidio_module_init: cannot allocate %d character devices.\n", MAXIMUM_AMOUNT_OF_ENCLAVES);
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

  praesidio_enclave_cdev = cdev_alloc();
  praesidio_enclave_cdev->ops = &praesidio_enclave_fops;

#ifdef PRAESIDIO_DEBUG
  printk(KERN_NOTICE "praesidio-driver: registered character device with major number %d and minor number %d.\n", MAJOR(praesidio_base_devnum), MINOR(praesidio_base_devnum));
#endif
  return 0;
}

module_init(praesidio_module_init);
module_exit(praesidio_module_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Marno van der Maas");
MODULE_DESCRIPTION("Driver to interface between user land and Praesidio enclaves.");
MODULE_VERSION("0.1");
