#include "parser/parser.h"
#include "ipvs/conn.h"
#include "ctrl.h"

#include <signal.h>

#define RTE_LOGTYPE_SIGNALS     RTE_LOGTYPE_USER1

static int signal_terminate_conns(struct dpvs_msg* msg);

static struct dpvs_msg_type signal_msg_type = {
        .type               = MSG_TYPE_SIG_TERM_CONNS,
        .prio               = MSG_PRIO_HIGH,
        .mode               = DPVS_MSG_MULTICAST,
        .unicast_msg_cb     = signal_terminate_conns,
        .multicast_msg_cb   = NULL,
};

static int signal_terminate_conns(struct dpvs_msg* msg) 
{

    dp_vs_conn_term_all();
    //flush pkts in hardware cache
    netif_hard_flush_by_lcore(rte_lcore_id());

    return EDPVS_OK;
}

static int graceful_exit()
{
    int err;
    struct dpvs_msg *msg = NULL;

    msg = msg_make(MSG_TYPE_SIG_TERM_CONNS,0,DPVS_MSG_MULTICAST,
                rte_lcore_id(),0, NULL);
    if (!msg) {
        goto out;
    }

    err = multicast_msg_send(msg, 0, NULL);
    if (err != EDPVS_OK)
        goto out;
    msg_destroy(&msg);

out:
    exit(0);
}


static inline void sighup(void)
{
    SET_RELOAD;
}

static inline void sigusr1(void)
{
    SET_RELOAD;
}

static void sig_callback(int sig)
{
    switch(sig) {
        case SIGUSR1:
            RTE_LOG(INFO, SIGNALS, "Got signal SIGUSR1, Reload Configure File.\n");
            sigusr1();
            break;
        case SIGHUP:
            RTE_LOG(INFO, SIGNALS, "Got signal SIGHUP, Reload Configure File.\n");
            sighup();
            break;
        case SIGINT:
            //Fall-through
        case SIGQUIT:
            //Fall-through
        case SIGTERM:
            RTE_LOG(INFO, SIGNALS, "Got Exit Signal type %d .\n",sig);
            RTE_LOG(INFO, SIGNALS, "CleanUP Conns…… Please Wait……\n");
            graceful_exit();// gracefull_exit will call exit().
        default:
            RTE_LOG(INFO, SIGNALS, "Unkown signal type %d.\n", sig);
            break;
    }
}



int signal_proc_init()
{
    int err;
    struct sigaction sig;

    // register SIGHUP signal handler 
    memset(&sig, 0, sizeof(struct sigaction));
    sig.sa_handler = sig_callback;
    sigemptyset(&sig.sa_mask);
    sig.sa_flags = 0;

    if (sigaction(SIGHUP, &sig, NULL) || sigaction(SIGUSR1, &sig, NULL) || sigaction(SIGINT, &sig, NULL)
                || sigaction(SIGTERM, &sig, NULL) || sigaction(SIGQUIT, &sig, NULL) ) {
        RTE_LOG(ERR, SIGNALS, "%s: signal handler register failed\n", __func__);
        return EDPVS_SYSCALL;
    }

    err = msg_type_register(&signal_msg_type);
    if(err != 0){
        RTE_LOG(ERR, SIGNALS, "%s: fail to register signal_msg_typ %s\n",
                    __func__, dpvs_strerror(err));
    }

    return EDPVS_OK;
}
