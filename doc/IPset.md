DPVS IPset
------

* [Concepts](#concepts)
* [Steps to use DPVS IPset](#usage)
* [Examples](#examples)
* [Develop a new IPset type](#develop)

<a id='concepts'/>

# Concepts

DPVS IPset is derived from [Linux IP sets](https://ipset.netfilter.org/index.html). It encompasses the mechanisms by which IP addresses, networks, (TCP/UDP) port numbers, MAC addresses, interface names or combinations of them in a way can be stored in a set. So that IP set ensures lightning speed when matching an entry against a set.

<a id='usage'/>

# Usage

## Command tool
```
dpip ipset { add | del | test } SETNAME ENTRY [ OPTIONS ]
dpip ipset add SETNAME TYPE [ OPTIONS ]
dpip ipset del SETNAME -D
dpip ipset { list | flush } [ SETNAME ]
```
There are two forms of IP segment:
* range: `ADDR-ADDR` <br>
* cidr: `ADDR/CIDR` <br>

<table>
    <tr>
        <th>element</th>
        <th>IPv4</th>
        <th>IPv6</th>
    </tr>
    <tr>
        <th>bitmap:ip</th>
        <th>o</th>
        <th>x</th>
    </tr>
    <tr>
        <th>bitmap:ip,mac</th>
        <th>x</th>
        <th>x</th>
    </tr>
    <tr>
        <th>hash:ip</th>
        <th>r</th>
        <th>c</th>
    </tr>
    <tr>
        <th>hash:net</th>
        <th>o</th>
        <th>c</th>
    </tr>
</table>

r -- support **range** <br>
c -- support **cidr** <br>
o -- support **both** <br>
x -- support **none** <br>

## Internal call
```C
/*
 * Function name : ipset_get
 * Description : Get the set pointer by name
 * Parameter :
 *        @name            name of the set
 * Return : pointer to the set   - success
 *          NULL                 - fail
 */
struct ipset *ipset_get(char *name);

/*
 * Function name : ipset_put
 * Description : Put back the set
 * Parameter :
 *        @set            pointer to the IPset
 */
static inline void
ipset_put(struct ipset *set)
{
    set->references--;
}

/*
 * Function name : elem_in_set
 * Description : Judge if element 'mbuf' is in the set
 * Parameter :
 *        @set            pointer to the IPset
 *        @param          pointer to the test parameter struct
 * Return :  1     - in set
 *           0     - NOT in set
 */
static inline int
elem_in_set(struct ipset *set, struct ipset_test_param *param)
{
    assert(set->variant->test);

    return set->variant->test(set, param);
}
```

<a id='examples'/>

# Examples
### 1. `bitmap:ip,mac` takes `ip and mac` pair as input. For bitmap type, the 'range' parameter **must be specified** when creating the set. 
* Flag `-F(--force)` could be used to force adding an element, which is useful for **adding a net range without failure caused by existing element** or rewrite the comment. 
* Flag `-D(--destroy)` is needed to destroy a set.
```
# dpip ipset add foo bitmap:ip,mac range 192.168.100.0/24 comment
# dpip ipset add foo 192.168.100.100,AA:BB:CC:DD:EE:FF comment "initial"
# dpip ipset add foo 192.168.100.100,AA:BB:CC:DD:EE:FF comment "overwrite" -F
# dpip ipset list
Name: foo
Type: bitmap:ip,mac
Header: range 192.168.100.0/24  comment
Size in memory: 1616
References: 0
Number of entries: 1
Members:
192.168.100.100 AA:BB:CC:DD:EE:FF  comment "overwrite"
# dpip ipset del foo -D
```

### 2. `hash:net,net` could be used as an ACL rule which takes `net,port,net,port` as input. It can be noted that if an 'IPv4 range' is taken as net parameter, it will be divided into several subnets automatically (If the 'delete range' is different with the 'add range', there may be problem).
* Flag `-v` shows the complete test result.
```
# dpip ipset add foo hash:net,net hashsize 300 maxelem 1000
# dpip ipset add foo 1.1.1.0-1.1.1.10,100,2.2.0.0/16,200
# dpip ipset list
Name: foo
Type: hash:net,net
Header: family inet  hashsize 256  maxelem 1000  
Size in memory: 4552
References: 0
Number of entries: 3
Members:
1.1.1.0/29,100,2.2.0.0/16,200  
1.1.1.8/31,100,2.2.0.0/16,200  
1.1.1.10/32,100,2.2.0.0/16,200
# dpip ipset test foo 1.1.1.5,100,2.2.200.200,200
true
# dpip ipset del foo 1.1.1.0/29,100,2.2.0.0/16,200
# dpip ipset test foo 1.1.1.5,100,2.2.200.200,200 -v
[sockopt_msg_recv] errcode set in socket msg#3300 header: not exist(-4)
1.1.1.5,100,2.2.200.200,200 is NOT in set foo
# dpip ipset flush foo
```

<a id='develop'/>

# Develop

Currently, there are 7 IPset types supported: `bitmap:ip`, `bitmap:ip,mac`, `bitmap:port`, `hash:ip`, `hash:net`, `hash:ip,port`, `hash:ip,port,ip`, `hash:net,iface` and `hash:net,net`. And it is convenient to create a custom type.

IPset module follows a "Deduction and Induction" architecture. Take "add an entry to a IPv4 hash:ip set" for example: firstly, the entry will go through the unified API `set->variant->adt()`, which is determined by the type and family of the set. Here it's bound to `hash_ip_adt4()` which will call the common low-level func `hash_adtfn()`. Eventually, type-specific low level funcs `do_hash(), do_compare()...` will do the real work.
<br>
![ipset arch](pics/ipset-arch.png)

To develop a new IPset type, first decide whether to use bitmap or hash.
## bitmap
Bitmap type supports only **IPv4**. It has better performance. But an IP range must be specified when creating and the corresponding memory is allocated even if there is no element yet. <br>
Take `bitmap:ip` as an example, the following structures and methods need to be implemented:
```C
struct ipset_type_variant bitmap_ip_variant = {
    .adt = bitmap_ip_adt,
    .test = bitmap_ip_test,
    .bitmap.do_del = bitmap_ip_do_del,
    .bitmap.do_test = bitmap_ip_do_test,
    .bitmap.do_list = bitmap_ip_do_list
};

struct ipset_type bitmap_ip_type = {
    .name       = "bitmap:ip",
    .create     = bitmap_ip_create,
    .destroy    = bitmap_destroy, 
    .flush      = bitmap_flush,
    .list       = bitmap_list,
    .adtfn      = bitmap_adtfn
};
```
To adapt the command tool `dpip`, the following methods need to be implemented:
```C
struct ipset_type types[TYPES] = {
    {
        .name = "bitmap:ip",
        .parse = net_parse,                     // How to parse arg
        .dump_header = bitmap_dump_header,      // How to dump header info
        .dump_member = net_dump_member          // How to dump set members
    },
    ...
}
```

## hash
Take `hash:net,iface` for example, the following structures and methods need to be implemented:
```C
/* Hash type support both IPv4 and IPv6, so two sets of functions are needed */
struct ipset_type_variant hash_net_variant4 = {
    .adt = hash_netiface_adt4,
    .test = hash_netiface_test,
    .hash.do_compare = hash_netiface_data_equal4,
    .hash.do_netmask = hash_data_netmask4,
    .hash.do_list = hash_netiface_do_list,
    .hash.do_hash = jhash_hashkey,
};

struct ipset_type hash_net_type = {
    .name       = "hash:net",
    .create     = hash_net_create,
    .destroy    = hash_destroy,
    .flush      = hash_flush,
    .list       = hash_list,
    .adtfn      = hash_adtfn,
};
```
Similarly, `dpip` should support this type. 
