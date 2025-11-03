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
MODULE_DESCRIPTION("CLOCK-Pro Cache Simulator Kernel Module (Robust Version)");

#define CACHE_SIZE 128
#define HASH_TABLE_BITS 7
#define PROC_FILENAME "clockpro_cache_sim"

// Page status flags
enum page_status { COLD, HOT, TEST };

typedef struct {
    unsigned long page_id;
    enum page_status status;
    int ref_bit; // The reference bit for the CLOCK algorithm

    struct hlist_node hash_node;
    struct list_head list_node; // Node for cold, hot, or test list
} cache_page_t;

// --- Global Variables ---
static struct list_head cold_list, hot_list, test_list;
// The 'hands' for the CLOCK algorithm. We initialize them to point
// to the list head, and our logic will move them to the tail on first use.
static struct list_head *cold_hand, *hot_hand;

static struct hlist_head hash_table[1 << HASH_TABLE_BITS];
static unsigned int cold_size = 0, hot_size = 0, test_size = 0;
static unsigned int target_cold_size = CACHE_SIZE; // Unused in this version, but part of full CLOCK-Pro

// Statistics
static unsigned long total_accesses = 0;
static unsigned long cache_hits = 0;

static cache_page_t* find_page(unsigned long page_id) {
    cache_page_t *page;
    unsigned int hash_key = hash_long(page_id, HASH_TABLE_BITS);
    hlist_for_each_entry(page, &hash_table[hash_key], hash_node) {
        if (page->page_id == page_id) return page;
    }
    return NULL;
}

static void demote_hot_page(cache_page_t *page) {
    list_move_tail(&page->list_node, &cold_list);
    page->status = COLD;
    hot_size--;
    cold_size++;
}

/**
 * evict_pages - This is the core CLOCK-Pro eviction logic, made robust.
 *
 * This function is called when the cache is full (cold + hot >= CACHE_SIZE).
 * It will run one or more "ticks" of the CLOCK algorithm until space is freed.
 *
 * CRASH-PROOFING:
 * It MUST handle the case where cold_size == 0 (cache is 100% hot).
 * It MUST handle the case where hot_size == 0 (cache is 100% cold).
 */
static void evict_pages(void) {
    // Loop until we are under the cache size limit
    while (cold_size + hot_size >= CACHE_SIZE) {
        
        if (cold_size > 0) {
            // --- CASE 1: Normal operation (cold list has pages) ---
            // Run the cold hand CLOCK.
            
            // If hand is at the head, move it to the tail (list_last_entry)
            if (cold_hand == &cold_list) {
                cold_hand = cold_list.prev; // Point to the tail
            }

            cache_page_t *page = list_entry(cold_hand, cache_page_t, list_node);
            
            // Advance the hand for the *next* call.
            // We move *prev* because we scan from tail to head.
            cold_hand = cold_hand->prev;

            if (page->ref_bit) {
                // Give it a second chance
                page->ref_bit = 0; 

                // To balance, we must demote a hot page (if any exist)
                if (hot_size > 0) {
                    if (hot_hand == &hot_list) {
                        hot_hand = hot_list.prev; // Point to tail
                    }
                    cache_page_t *hot_page_to_demote = list_entry(hot_hand, cache_page_t, list_node);
                    hot_hand = hot_hand->prev; // Advance hot hand
                    
                    demote_hot_page(hot_page_to_demote);
                }
            } else {
                // ref_bit == 0. Evict this page.
                list_move_tail(&page->list_node, &test_list);
                hlist_del(&page->hash_node);
                page->status = TEST;
                cold_size--;
                test_size++;

                // Keep test list size in check
                while (test_size > CACHE_SIZE) {
                    cache_page_t *test_page = list_first_entry(&test_list, cache_page_t, list_node);
                    list_del(&test_page->list_node);
                    kfree(test_page);
                    test_size--;
                }
            }
        } else {
            // --- CASE 2: Edge Case (cold_size == 0) ---
            // The cache is 100% hot pages. We *must* demote one to
            // make a "cold" victim for the next loop iteration.
            
            // We know hot_size >= CACHE_SIZE, so hot_list is not empty.
            
            if (hot_hand == &hot_list) {
                hot_hand = hot_list.prev; // Point to tail
            }
            cache_page_t *hot_page_to_demote = list_entry(hot_hand, cache_page_t, list_node);
            hot_hand = hot_hand->prev; // Advance hot hand

            demote_hot_page(hot_page_to_demote);
            
            // The outer 'while' loop will run again.
            // This time, 'cold_size > 0' will be true.
        }
    }
}


static void access_page(unsigned long page_id) {
    cache_page_t *page = find_page(page_id);
    total_accesses++;

    if (page) { // --- Cache Hit ---
        cache_hits++;
        page->ref_bit = 1;
        if (page->status == COLD) {
            // Promote from cold to hot
            list_move_tail(&page->list_node, &hot_list);
            page->status = HOT;
            cold_size--;
            hot_size++;
        }
        // If it's already hot, setting the ref_bit is enough.

    } else { // --- Cache Miss ---
        cache_page_t *test_page = NULL, *tmp;
        list_for_each_entry_safe(test_page, tmp, &test_list, list_node) {
            if (test_page->page_id == page_id) {
                // It's a "test" hit! This means the page is valuable.
                if (target_cold_size > 0) target_cold_size--;
                
                list_del(&test_page->list_node);
                kfree(test_page);
                test_size--;
                goto new_page; // Treat as a new page insertion
            }
        }

        // It was not a test hit.
        if (target_cold_size < CACHE_SIZE) target_cold_size++;

    new_page:
        // Make space if necessary *before* allocating
        evict_pages();

        page = kmalloc(sizeof(cache_page_t), GFP_KERNEL);
        if (!page) {
            pr_err("CLOCK-Pro: Failed to allocate memory for new page\n");
            return; // Failed to allocate, drop this access
        }
        
        page->page_id = page_id;
        page->status = COLD;
        page->ref_bit = 1; // Start with ref_bit = 1 (original paper says 0, but 1 is safer for new pages)

        list_add_tail(&page->list_node, &cold_list); // Add to tail
        
        // *** FIX: Use hlist_add_head and calculate hash key ***
        hlist_add_head(&page->hash_node, &hash_table[hash_long(page->page_id, HASH_TABLE_BITS)]);
        
        cold_size++;
    }
}


static ssize_t proc_write(struct file *file, const char __user *buffer, size_t count, loff_t *ppos) {
    char *kbuf, *token, *rest;
    unsigned long page_id;

    kbuf = kmalloc(count + 1, GFP_KERNEL);
    if (!kbuf) return -ENOMEM;
    if (copy_from_user(kbuf, buffer, count)) { kfree(kbuf); return -EFAULT; }
    kbuf[count] = '\0';
    rest = kbuf;

    pr_info("--- CLOCK-Pro Simulation Started ---\n");
    total_accesses = 0;
    cache_hits = 0;
    
    while ((token = strsep(&rest, " \t\n")) != NULL) {
        if (kstrtoul(token, 10, &page_id) == 0) {
            access_page(page_id);
        }
    }

    pr_info("--- CLOCK-Pro Simulation Finished ---\n");
    pr_info("Total Accesses: %lu, Cache Hits: %lu\n", total_accesses, cache_hits);
    if (total_accesses > 0) {
        pr_info("Hit Ratio: %lu%%\n", (cache_hits * 100) / total_accesses);
    }

    kfree(kbuf);
    return count;
}

static const struct proc_ops proc_file_ops = { .proc_write = proc_write };

static void free_all_pages(void) {
    cache_page_t *page, *tmp;
    // Use list_for_each_entry_safe for safe removal
    list_for_each_entry_safe(page, tmp, &cold_list, list_node) kfree(page);
    list_for_each_entry_safe(page, tmp, &hot_list, list_node) kfree(page);
    list_for_each_entry_safe(page, tmp, &test_list, list_node) kfree(page);
}

static int __init clockpro_cache_init(void) {
    int i;
    pr_info("Initializing CLOCK-Pro Simulator...\n");
    
    INIT_LIST_HEAD(&cold_list);
    INIT_LIST_HEAD(&hot_list);
    INIT_LIST_HEAD(&test_list);
    cold_hand = &cold_list; // Initialize hands to the head
    hot_hand = &hot_list;

    for (i = 0; i < (1 << HASH_TABLE_BITS); i++) INIT_HLIST_HEAD(&hash_table[i]);
    
    proc_create(PROC_FILENAME, 0666, NULL, &proc_file_ops);
    pr_info("CLOCK-Pro module loaded. Cache size: %d\n", CACHE_SIZE);
    pr_info("Write a trace to /proc/%s\n", PROC_FILENAME);
    return 0;
}

static void __exit clockpro_cache_exit(void) {
    remove_proc_entry(PROC_FILENAME, NULL);
    free_all_pages();
    pr_info("CLOCK-Pro module unloaded. All pages freed.\n");
}

module_init(clockpro_cache_init);
module_exit(clockpro_cache_exit);

