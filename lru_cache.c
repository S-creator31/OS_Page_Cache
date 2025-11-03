#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("LRU Cache Simulator Kernel Module");

#define CACHE_SIZE 128 // The total number of pages the cache can hold
#define HASH_TABLE_BITS 7 // Hash table will have 2^7 = 128 buckets
#define PROC_FILENAME "lru_cache_sim"

// Structure for a cached page
typedef struct {
    unsigned long page_id;  // The identifier for the page
    struct hlist_node hash_node; // Node for the hash table
    struct list_head lru_list;   // Node for the LRU list
} cache_page_t;

// --- Global Variables ---
static struct list_head lru_list_head; // Head of the LRU list (MRU at head, LRU at tail)
static struct hlist_head hash_table[1 << HASH_TABLE_BITS];
static unsigned int cache_occupancy = 0;

// Statistics
static unsigned long total_accesses = 0;
static unsigned long cache_hits = 0;

// Function to find a page in the cache
static cache_page_t* find_page(unsigned long page_id) {
    cache_page_t *page;
    unsigned int hash_key = hash_long(page_id, HASH_TABLE_BITS);

    hlist_for_each_entry(page, &hash_table[hash_key], hash_node) {
        if (page->page_id == page_id) {
            return page;
        }
    }
    return NULL;
}

// Function to simulate a page access
static void access_page(unsigned long page_id) {
    cache_page_t *page = find_page(page_id);
    total_accesses++;

    if (page) { // --- Cache Hit ---
        cache_hits++;
        // Move the accessed page to the front (head) of the LRU list
        list_move(&page->lru_list, &lru_list_head);
    } else { // --- Cache Miss ---
        if (cache_occupancy >= CACHE_SIZE) {
            // Evict the least recently used page (from the tail)
            cache_page_t *lru_page = list_last_entry(&lru_list_head, cache_page_t, lru_list);
            list_del(&lru_page->lru_list);
            hlist_del(&lru_page->hash_node);
            kfree(lru_page);
            cache_occupancy--;
        }

        // Add the new page to the cache
        page = kmalloc(sizeof(cache_page_t), GFP_KERNEL);
        if (!page) {
            pr_err("Failed to allocate memory for new page\n");
            return;
        }
        page->page_id = page_id;
        
        // Add to front of LRU list and hash table
        list_add(&page->lru_list, &lru_list_head);
        hlist_add_head(&page->hash_node, &hash_table[hash_long(page->page_id, HASH_TABLE_BITS)]);
        cache_occupancy++;
    }
}

// This function is called when the /proc file is written to
static ssize_t proc_write(struct file *file, const char __user *buffer, size_t count, loff_t *ppos) {
    char *kbuf;
    char *token;
    char *rest;
    unsigned long page_id;

    if (count == 0) return 0;

    kbuf = kmalloc(count + 1, GFP_KERNEL);
    if (!kbuf) return -ENOMEM;

    if (copy_from_user(kbuf, buffer, count)) {
        kfree(kbuf);
        return -EFAULT;
    }
    kbuf[count] = '\0';
    rest = kbuf;

    // Reset stats for a new trace
    total_accesses = 0;
    cache_hits = 0;
    
    pr_info("--- LRU Simulation Started ---\n");
    // Parse the space-separated page IDs from the buffer
    while ((token = strsep(&rest, " \t\n")) != NULL) {
        if (kstrtoul(token, 10, &page_id) == 0) {
            access_page(page_id);
        }
    }

    // Print final statistics
    pr_info("--- LRU Simulation Finished ---\n");
    pr_info("Total Accesses: %lu\n", total_accesses);
    pr_info("Cache Hits: %lu\n", cache_hits);
    if (total_accesses > 0) {
        pr_info("Hit Ratio: %lu%%\n", (cache_hits * 100) / total_accesses);
    } else {
        pr_info("Hit Ratio: 0%%\n");
    }

    kfree(kbuf);
    return count;
}


// --- Module Initialization and Cleanup ---

static const struct proc_ops proc_file_ops = {
    .proc_write = proc_write,
};

static int __init lru_cache_init(void) {
    int i;
    INIT_LIST_HEAD(&lru_list_head);
    for (i = 0; i < (1 << HASH_TABLE_BITS); i++) {
        INIT_HLIST_HEAD(&hash_table[i]);
    }
    proc_create(PROC_FILENAME, 0666, NULL, &proc_file_ops);
    pr_info("LRU Cache Simulator module loaded. Cache size: %d\n", CACHE_SIZE);
    pr_info("Write a trace to /proc/%s to start simulation.\n", PROC_FILENAME);
    return 0;
}

static void __exit lru_cache_exit(void) {
    cache_page_t *page, *tmp;
    
    // Free all allocated pages
    list_for_each_entry_safe(page, tmp, &lru_list_head, lru_list) {
        list_del(&page->lru_list);
        hlist_del(&page->hash_node);
        kfree(page);
    }

    remove_proc_entry(PROC_FILENAME, NULL);
    pr_info("LRU Cache Simulator module unloaded.\n");
}

module_init(lru_cache_init);
module_exit(lru_cache_exit);
