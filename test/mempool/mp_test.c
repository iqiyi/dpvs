#include <mempool.h>

//#define DPVS_MEMPOOL_TEST_STEP

int main(int argc, char *argv[])
{
    __rte_unused int i, err;
    void *ptr;
    __rte_unused int obj_sz1, obj_sz2, mem;

    struct dpvs_mempool *pool;

    err = rte_eal_init(argc, argv);
    if (err < 0)
        rte_exit(EXIT_FAILURE, "Fail to init eal!\n");

#ifdef DPVS_MEMPOOL_TEST_STEP
    pool = dpvs_mempool_create("dpvs_mp_test", 32, 65536, 1024);
    if (!pool) {
        fprintf(stderr, "dpvs_mempool_create failed!\n");
        return 1;
    }

    ptr = dpvs_mempool_get(pool, 10);
    dpvs_mempool_put(pool, ptr); 
    
    ptr = dpvs_mempool_get(pool, 100);
    dpvs_mempool_put(pool, ptr); 
    
    ptr = dpvs_mempool_get(pool, 1000);
    dpvs_mempool_put(pool, ptr);
    
    ptr = dpvs_mempool_get(pool, 10000);
    dpvs_mempool_put(pool, ptr);

    ptr = dpvs_mempool_get(pool, 100000);
    dpvs_mempool_put(pool, ptr);

    dpvs_mempool_destroy(pool);
#else
    for (obj_sz1=8, obj_sz2=1024, mem=100; obj_sz2 < 64000; obj_sz1 += 32, obj_sz2 += 256, mem += 20) {
        pool = dpvs_mempool_create("dpvs_mp_test", obj_sz1, obj_sz2, mem);
        if (!pool) {
            fprintf(stderr, "dpvs_mempool_create failed!\n");
            return 1;
        }
    
        for (i = 0; i < 10000; i++) {
            ptr = dpvs_mempool_get(pool, 10);
            dpvs_mempool_put(pool, ptr);
    
            ptr = dpvs_mempool_get(pool, 100);
            dpvs_mempool_put(pool, ptr);
    
            ptr = dpvs_mempool_get(pool, 1000);
            dpvs_mempool_put(pool, ptr);
    
            ptr = dpvs_mempool_get(pool, 10000);
            dpvs_mempool_put(pool, ptr);
        }
    
        dpvs_mempool_destroy(pool);
    }
#endif

    printf("Finished!\n");
    return 0;
}
