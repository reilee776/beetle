#include "nd_nix_log.h"
#include <linux/rbtree.h>
#include <linux/slab.h>


//#define MAX_LOGS 256
//#define LOG_SIZE 1024
//static char *log_buffer[MAX_LOGS];
//static int log_count = 0;

void add_log(const char *log) {
	int i = 0;
	char *new_log = kmalloc(LOG_SIZE, GFP_KERNEL);
	snprintf(new_log, LOG_SIZE, "%s", log);

	if (nd_log_count < MAX_LOGS) {

		log_buffer[nd_log_count] = new_log; 
		nd_log_count++;
	} else {
		kfree(log_buffer[0]); 

		for (i = 1; i < MAX_LOGS; i++) {

			log_buffer[i - 1] = log_buffer[i];
		}

		log_buffer[MAX_LOGS - 1] = new_log;
	}
}


/*
void add_log(const char *msg) {
	struct log_entry *new_log;

	if (nd_log_count >= MAX_LOGS) {
		// delete old log
		struct log_entry *old_log = list_first_entry(&log_list.list, struct log_entry, list);
		list_del(&old_log->list);
		kfree(old_log);
		nd_log_count--;
	}

	// add new log
	new_log = kmalloc(sizeof(struct log_entry), GFP_KERNEL);
	if (new_log) {
		printk ("insert log...[%s]\n", msg);
		strncpy(new_log->message, msg, LOG_MSG_SIZE);
		INIT_LIST_HEAD (&new_log->list);
		list_add_tail(&new_log->list, &log_list.list);
		nd_log_count++;
	}
}
*/
ssize_t get_logs(char *pOutput)
{
	struct log_entry *log;
	struct list_head *pos, *next;
        size_t total_bytes = 0;
	char log_buffer[MAX_LOGS * LOG_MSG_SIZE];
	char *ptr = log_buffer;
	//char *ptr = pOutput;

	if (list_empty (&log_list.list))
	{
		return -1;
	}
	
//	mutex_lock(&log_mutex);	
	list_for_each_safe (pos, next, &log_list.list)		{

		log = list_entry (pos, struct log_entry, list);
		if (log)
		{
			size_t len = strnlen(log->message, LOG_MSG_SIZE);
			if (total_bytes + len + 1 < sizeof (log_buffer)) {
			    strcpy(ptr, log->message);
			    ptr += len;
			    *ptr++ = '\n'; // new line
			    total_bytes += len + 1;

			    printk ("get_logs cunction ..3");
			}

		}
	}
	printk ("get_logs function ..4(%s)\n", log_buffer);
	
	*ptr = '\0';
	strncpy(pOutput, log_buffer, total_bytes);
	pOutput[total_bytes] = '\0';
	//pOutput = log_buffer;
	
//	mutex_unlock(&log_mutex);

	return total_bytes;
/*
	struct log_entry *log;
        size_t total_bytes = 0;
        //char log_buffer[MAX_LOGS * LOG_MSG_SIZE];
        //char *ptr = log_buffer;
	char *ptr = pOutput;

	printk("get_logs function...1(%d)\n", nd_log_count);
        mutex_lock(&log_mutex);
        list_for_each_entry(log, &log_list, list) {
		printk ("get_logs function ...2\n");
                size_t len = strnlen(log->message, LOG_MSG_SIZE);
                if (total_bytes + len + 1 < (MAX_LOGS * LOG_MSG_SIZE)) {
                    strcpy(ptr, log->message);
                    ptr += len;
                    *ptr++ = '\n'; // new line
                    total_bytes += len + 1;

		    printk ("get_logs cunction ..3");
                }
        }
        mutex_unlock(&log_mutex);

	printk ("get_logs function ..4(%s)(%s)\n", pOutput,ptr);

	return total_bytes;
	
*/	
}
/*
ssize_t get_logs(char __user *buf, size_t count) {
	struct log_entry *log;
	size_t total_bytes = 0;
	char log_buffer[MAX_LOGS * LOG_MSG_SIZE];
	char *ptr = log_buffer;

	mutex_lock(&log_mutex);
	list_for_each_entry(log, &log_list, list) {
		size_t len = strnlen(log->message, LOG_MSG_SIZE);
		if (total_bytes + len + 1 < sizeof(log_buffer)) {
		    strcpy(ptr, log->message);
		    ptr += len;
		    *ptr++ = '\n'; // new line
		    total_bytes += len + 1;
		}
	}
	mutex_unlock(&log_mutex);

	if (copy_to_user(buf, log_buffer, total_bytes)) {
		return -EFAULT;
	}

	return total_bytes;
}
*/

