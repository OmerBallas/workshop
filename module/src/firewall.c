
#include "fw.h"
#include "state.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Omer Ballas");

static struct nf_hook_ops hook_fw;
static struct nf_hook_ops hook_local;

static rule_t rules_table[MAX_RULES];
static int table_size = 0;
static int major_number;
static struct class* fw_class = NULL;
static struct device* rules_device = NULL;
static struct device* log_device = NULL;
static struct device* conns_device = NULL;
static struct device* proxy_driver = NULL;
static struct device* ftp_driver = NULL;


static unsigned int num_logs = 0;


//structs for list
typedef struct {
	struct list_head list;
	log_row_t log_row;
} log_list_node;

typedef struct 
{
	struct list_head list;
	connection_table_row_t* ctr;
} connection_table_node;


//list init
struct list_head log_list = LIST_HEAD_INIT(log_list); // head of log list (for linux\list)
struct list_head connection_table_list =  LIST_HEAD_INIT(connection_table_list); //head of connection table (for linux\list)



//checks if the ips are equal under the mask
int ip_check( __be32 ip1, __be32 ip2, __be32 mask) {
    if (mask == 0){ return 1;}
    return (ip1 & mask) == (ip2 & mask);
}

//check the port in the rule
int port_check(unsigned short rport, __be16 pport) {
    if (rport == PORT_ANY) {return 1;}
    if (rport == PORT_ABOVE_1023) {return (ntohs(pport) >= 1023);}
    return rport == ntohs(pport);
}

//checks if the packet belongs to the rule
int rule_check(struct sk_buff *skb, rule_t *rule, direction_t direction) {
    struct iphdr *ip_header = ip_hdr(skb);
    prot_t packet_protocol = ip_header->protocol;
    if (!ip_check(ip_header->saddr, rule->src_ip, rule->src_prefix_mask)) return 0;
    if (!ip_check(ip_header->daddr, rule->dst_ip, rule->dst_prefix_mask)) return 0;
    
    if ((rule->direction != DIRECTION_ANY) && (rule->direction != direction)) {
		return 0;
	}
    if (rule->protocol != PROT_ANY) {
        if ((packet_protocol == PROT_TCP) || (packet_protocol == PROT_UDP) || (packet_protocol == PROT_ICMP))
        {
            if (rule->protocol != packet_protocol)
            {
                return 0;
            }
            
        }
        else if(rule->protocol != PROT_OTHER){
            return 0;
        }
        
    }
    if (rule->src_port != PORT_ANY || rule->dst_port != PORT_ANY) {
        unsigned int s_port, d_port;
        int check_ports = 0; // check the port only for TCP, UDP
        if (packet_protocol == PROT_TCP) {
            struct tcphdr *tcp_header = tcp_hdr(skb);
            s_port = ntohs(tcp_header->source);
            d_port = ntohs(tcp_header->dest);
            check_ports = 1;
        } else if (packet_protocol == PROT_UDP) {
            struct udphdr *udp_header = udp_hdr(skb);
            s_port = ntohs(udp_header->source);
            d_port = ntohs(udp_header->dest);
            check_ports = 1;
        } 

        if (check_ports) {
            if (!port_check(rule->src_port, s_port)) {return 0;}
            if (!port_check(rule->dst_port, d_port)) {return 0;}
        }
    }

    if (packet_protocol == PROT_TCP && (rule->ack != ACK_ANY)) {
        struct tcphdr *tcp_header = tcp_hdr(skb);
        int ack = tcp_header->ack;
        if (rule->ack == ACK_YES) {
            if (!ack) return 0;
        } else if (ack) return 0;
    }

    return 1;
}

int validate_prefix(__be32 prefix_mask, __u8 prefix_size) {
	//checks that the mask is fine in little endiean, using ULL to not overflow
	return (1ULL << 32) - (1ULL << (32 - prefix_size)) == ntohl(prefix_mask);
}
//change 
int validate_rule(rule_t* rule) {
	if (!strlen(rule->rule_name)) {
		return 0; // check if has a name
	}

	// direction
	if ((rule->direction != DIRECTION_ANY) && (rule->direction != DIRECTION_OUT) && (rule->direction != DIRECTION_IN))
    {
        return 0;
    }
    

	// checks that the mask is fine in little endiean
	
    if (!validate_prefix(rule->src_prefix_mask, rule->src_prefix_size) ||
		!validate_prefix(rule->dst_prefix_mask, rule->dst_prefix_size)) {
        printk(KERN_INFO "prefix err\n");
		return 0;
	}
    

	// check protocol
	if((rule->protocol != PROT_TCP) && (rule->protocol != PROT_UDP) && (rule->protocol != PROT_ICMP) && (rule->protocol != PROT_ANY)){
        return 0;
    }

	// check ack
	if((rule->ack != ACK_ANY) && (rule->ack != ACK_YES) && (rule->ack != ACK_NO)){
        return 0;
    }

	// check action
	if ((rule->action != NF_DROP) && (rule->action != NF_ACCEPT))
    {
        return 0;
    }
	return 1;
}


//adds a log row to the list
void add_row(log_row_t log_row) {
	log_list_node* log_node = kmalloc(sizeof(log_list_node), GFP_KERNEL);
	log_node->log_row = log_row;
	list_add_tail(&log_node->list, &log_list);
	num_logs++;
}

//gets the packet, the action and the reason. log them.
void update_log(struct sk_buff* skb, reason_t reason, __u8 action) {
    log_list_node *log_node;
    log_row_t row;
    unsigned char protocol;     	
	__be32 src_ip;		  	
	__be32 dst_ip;		  	
	__be16 src_port;	  	
	__be16 dst_port;	 
    struct timespec64 time; 
    struct iphdr *ip_header = ip_hdr(skb);
    src_ip = ip_header->saddr;
	dst_ip = ip_header->daddr;
	protocol = ip_header->protocol;
    if(protocol == PROT_ICMP){
        src_port = 0; dst_port = 0;
    }
    else if(protocol == PROT_TCP){
        src_port = ntohs(tcp_hdr(skb)->source); dst_port = ntohs(tcp_hdr(skb)->dest);
    }
    else{
        src_port = ntohs(udp_hdr(skb)->source); dst_port = ntohs(udp_hdr(skb)->dest);
    }
    //check if similar log exists
    list_for_each_entry(log_node, &log_list, list){
        row = log_node->log_row;
        if ((src_ip == row.src_ip) && (dst_ip == row.dst_ip) && (protocol == row.protocol) && (action == row.action) && (src_port == row.src_port) && (dst_port == row.dst_port) && (reason == row.reason)){
            log_node->log_row.count += 1;
            ktime_get_real_ts64(&time);
            log_node->log_row.timestamp = time.tv_sec;
            return;
        }
        
    }
    //add new log
    row.timestamp = time.tv_sec;
	row.protocol = protocol;
	row.action = action;
	row.src_ip = src_ip;
	row.dst_ip = dst_ip;
	row.src_port = src_port;
	row.dst_port = dst_port;
	row.reason = reason;
	row.count = 1;
	add_row(row);
}

//frees the log.
void free_log_list(void){
    log_list_node *log_node, *tmp_holder;
	list_for_each_entry_safe(log_node, tmp_holder, &log_list, list) {
			list_del(&log_node->list);
			kfree(log_node);
		}
	num_logs = 0;
}

//adds new connection to the list.
void add_connection(connection_table_row_t* ctr) {
	connection_table_node* ct_node = kmalloc(sizeof(connection_table_node), GFP_KERNEL);
	ct_node->ctr = ctr;
	list_add_tail(&ct_node->list, &connection_table_list);
}

//cleans the connections
void free_connection_table_list(void){
    connection_table_node *ct_node, *tmp_holder;
	list_for_each_entry_safe(ct_node, tmp_holder, &connection_table_list, list) {
				list_del(&ct_node->list);
				kfree(ct_node->ctr);
				kfree(ct_node);
		}
}

//deletes from the table the closed connections.
void del_closed_conns(void){
	connection_table_node *ct_node, *tmp_holder;
	connection_table_row_t* ctr;
	list_for_each_entry_safe(ct_node,tmp_holder, &connection_table_list, list){
		ctr = ct_node->ctr;
		if (ctr->state == STATE_CLOSED)
		{
			list_del(&ct_node->list);
			kfree(ct_node->ctr);
			kfree(ct_node);
		}
	}
}

void change_dest(struct sk_buff *skb,unsigned int new_dest_ip, unsigned short new_dest_port){
	struct iphdr *ip_header = ip_hdr(skb);
	struct tcphdr *tcp_header = tcp_hdr(skb);
	/* Change the routing */
	ip_header->daddr = new_dest_ip; //change to yours IP
	tcp_header->dest = htons(new_dest_port); //change to yours listening port

	/* Fix IP header checksum */
	ip_header->check = 0;
	ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);

	/*
	* From Linux doc here: https://elixir.bootlin.com/linux/v4.15/source/include/linux/skbuff.h#L90
	* CHECKSUM_NONE:
	*
	*   Device did not checksum this packet e.g. due to lack of capabilities.
	*   The packet contains full (though not verified) checksum in packet but
	*   not in skb->csum. Thus, skb->csum is undefined in this case.
	*/
	skb->ip_summed = CHECKSUM_NONE;
	skb->csum_valid = 0;

	/* Linearize the skb */
	if (skb_linearize(skb) < 0) {
		/* Handle error*/
		printk(KERN_INFO "linearize error");
	}
	/* Re-take headers. The linearize may change skb's pointers */
	ip_header = ip_hdr(skb);
	tcp_header = tcp_hdr(skb);

	/* Fix TCP header checksum */
	int tcplen = (ntohs(ip_header->tot_len) - ((ip_header->ihl) << 2));
	tcp_header->check = 0;
	tcp_header->check = tcp_v4_check(tcplen, ip_header->saddr, ip_header->daddr, csum_partial((char *)tcp_header, tcplen, 0));
}

void change_source(struct sk_buff *skb,unsigned int new_source_ip, unsigned short new_source_port){
	struct iphdr *ip_header = ip_hdr(skb);
	struct tcphdr *tcp_header = tcp_hdr(skb);
	/* Change the routing */
	ip_header->saddr = new_source_ip; //change to yours IP
	tcp_header->source = htons(new_source_port); //change to yours listening port

	/* Fix IP header checksum */
	ip_header->check = 0;
	ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);

	/*
	* From Linux doc here: https://elixir.bootlin.com/linux/v4.15/source/include/linux/skbuff.h#L90
	* CHECKSUM_NONE:
	*
	*   Device did not checksum this packet e.g. due to lack of capabilities.
	*   The packet contains full (though not verified) checksum in packet but
	*   not in skb->csum. Thus, skb->csum is undefined in this case.
	*/
	skb->ip_summed = CHECKSUM_NONE;
	skb->csum_valid = 0;

	/* Linearize the skb */
	if (skb_linearize(skb) < 0) {
		/* Handle error*/
	}
	/* Re-take headers. The linearize may change skb's pointers */
	ip_header = ip_hdr(skb);
	tcp_header = tcp_hdr(skb);

	/* Fix TCP header checksum */
	int tcplen = (ntohs(ip_header->tot_len) - ((ip_header->ihl) << 2));
	tcp_header->check = 0;
	tcp_header->check = tcp_v4_check(tcplen, ip_header->saddr, ip_header->daddr, csum_partial((char *)tcp_header, tcplen, 0));
}

ssize_t display_logs(struct file *filp, char *buff, size_t len, loff_t *offp) {
    int i = 0;
	log_list_node *log_node;
    log_list_node *ret;

    //read only from log file
	unsigned int minor_num = iminor(file_inode(filp));
	if (minor_num != MINOR_LOG) {
        printk(KERN_INFO "minor err\n");
		return -EFAULT; 
	}
	//read one row at a time
	if (len != sizeof(log_row_t)) {
        printk(KERN_INFO "lenn err\n");
		return -EINVAL;
	}
	//eof
	if (*offp >= num_logs * sizeof(log_row_t)) {
        printk(KERN_INFO "EOF\n");
		*offp = 0;
		return 0; // EOF
	}
    if ((((int)*offp) % ((int)sizeof(log_row_t))))
    {
        printk(KERN_INFO "mod err\n");
        return -EFAULT;
    }
	list_for_each_entry(log_node, &log_list, list) { // iterates through the log list to find the right log row matching the offset
			if (*offp == i * sizeof(log_row_t)) {
				ret = log_node;
				break;
			}
            else{
                i++;
            }
		}	
	if (copy_to_user(buff, &ret->log_row, sizeof(log_row_t))) { // send the data to the user through 'copy_to_user'
		 printk(KERN_INFO "copy err\n");
        return -EFAULT;
	}

	// update the helper variables (file offset, and the variables for the optimization)
	*offp += sizeof(log_row_t);
	return sizeof(log_row_t);
}


ssize_t display_rules(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	memcpy(buf, rules_table, table_size * sizeof(rule_t));
    return (table_size * sizeof(rule_t));

	
}

ssize_t modify_logs(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{
    free_log_list();
	return count;
}
ssize_t modify_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{

    int i, new_num_rules;
    //validate size of data is a possible size of a table
	if (((int)count) % ((int)sizeof(rule_t))) {
		printk(KERN_INFO "Error in size of table");
		return 0;
	}

	// not trusting the user
	new_num_rules = ((int)count) / ((int)sizeof(rule_t));
	if (new_num_rules > MAX_RULES) {
		printk(KERN_INFO "Error rules table is too large");
		return 0;
	}
    rule_t* new_rules_table = (rule_t*)buf;
	for (i = 0; i < new_num_rules; i++) {
		if (!validate_rule(&(new_rules_table[i]))) {
			printk(KERN_INFO "Error invalid rule: %d\n", i);
			return 0;
		}
	}
    
    memset(rules_table, 0, MAX_RULES * sizeof(rule_t));
    table_size = new_num_rules;
	memcpy(rules_table, new_rules_table, table_size * sizeof(rule_t));
	return count;
}


ssize_t display_conns(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	int i = 0;
	int ret;
	connection_table_node* ct_node;
	list_for_each_entry(ct_node, &connection_table_list, list) { // iterates through the log list to find the right log row matching the offset
		memcpy(buf + (i * sizeof(connection_table_row_t)), (ct_node->ctr),sizeof(connection_table_row_t));
		i++;	
	

	}
	return i * sizeof(connection_table_row_t);
}

//adds to the connection table the port of the local process
ssize_t modify_proxy(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{
	connection_table_row_t* new_ctr = (connection_table_row_t*)buf;
	connection_table_node* ct_node;
	connection_table_row_t* ctr_temp;
			list_for_each_entry(ct_node, &connection_table_list, list){
					ctr_temp = ct_node->ctr;
					if ((ctr_temp->src_ip == new_ctr->src_ip) && (ctr_temp->dst_ip == new_ctr->dst_ip) && (ctr_temp->src_port == new_ctr->src_port) && (ctr_temp->dst_port == new_ctr->dst_port))
					{
						ct_node->ctr->local_port = new_ctr->local_port;
						ct_node->ctr->twin->local_port = new_ctr->local_port;
						return count;
					}
				}
	printk(KERN_INFO "No connection found");
	return 0;
}

//adds the port that the clients listens of for ftp data transfer to the connection table.
ssize_t modify_ftp(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{
	connection_table_row_t* ctr = kmalloc(sizeof(connection_table_row_t), GFP_KERNEL);
	connection_table_row_t* ctr_twin = kmalloc(sizeof(connection_table_row_t), GFP_KERNEL);

	ctr->src_ip = ((connection_table_row_t*)buf)->src_ip;
	ctr->dst_ip = ((connection_table_row_t*)buf)->dst_ip;
	ctr->src_port = ((connection_table_row_t*)buf)->src_port;
	ctr->dst_port = ((connection_table_row_t*)buf)->dst_port;
	ctr->state = STATE_SYN_SENT;
	ctr->proxy_state = 0;
	ctr->local_port = 0;

	ctr_twin->dst_ip = ((connection_table_row_t*)buf)->src_ip;
	ctr_twin->src_ip = ((connection_table_row_t*)buf)->dst_ip;
	ctr_twin->dst_port = ((connection_table_row_t*)buf)->src_port;
	ctr_twin->src_port = ((connection_table_row_t*)buf)->dst_port;
	ctr_twin->state = STATE_LISTEN;
	ctr_twin->proxy_state = 0;
	ctr_twin->local_port = 0;

	ctr->twin = ctr_twin;
	ctr_twin->twin = ctr;
	add_connection(ctr);
	add_connection(ctr_twin);
	return 0;
}

static DEVICE_ATTR(rules, S_IRUSR | S_IRGRP | S_IWUSR | S_IWGRP , display_rules, modify_rules);
static DEVICE_ATTR(reset, S_IWUSR | S_IWGRP  , NULL, modify_logs);
static DEVICE_ATTR(conns, S_IRUSR | S_IRGRP, display_conns, NULL);
static DEVICE_ATTR(proxy, S_IWUSR | S_IWGRP ,NULL,  modify_proxy);
static DEVICE_ATTR(ftp, S_IWUSR | S_IWGRP ,NULL,  modify_ftp);


static struct file_operations fops= {
	.owner = THIS_MODULE,
    .read = display_logs
};

//the hook
static unsigned int fw_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    
	//checks if the packet is ipv4
    struct ethhdr *eth_header = eth_hdr(skb);
    if (eth_header->h_proto != htons(ETH_P_IP))
    {
        return NF_ACCEPT;
    }

    struct iphdr *ip_header = ip_hdr(skb);
    prot_t packet_protocol = ip_header->protocol;
    int i;
	//checks if the packet is loopback
    if(ip_check(ip_header->daddr,LOOPBACK_IP, LOOPBACK_MASK))
    {
        return NF_ACCEPT;
    }
	
    //checks if the packet is not one of TCP,UDP,ICMP
	if ((packet_protocol != PROT_TCP) && (packet_protocol != PROT_UDP) && (packet_protocol != PROT_ICMP)){

        return NF_ACCEPT;
    }
	//checks for xmas packet
	if ((packet_protocol == PROT_TCP) && ((tcp_flag_word(tcp_hdr(skb)) & (TCP_FLAG_FIN | TCP_FLAG_URG | TCP_FLAG_PSH)) == ((TCP_FLAG_FIN | TCP_FLAG_URG | TCP_FLAG_PSH))))
        {	
			printk(KERN_INFO "found xms");
            update_log(skb, REASON_XMAS_PACKET, NF_DROP);
            return NF_DROP;
        }
    
	//check connection table
    if ((packet_protocol == PROT_TCP) && (tcp_flag_word(tcp_hdr(skb)) & TCP_FLAG_ACK)) {
		struct tcphdr *tcp_header = tcp_hdr(skb);
		unsigned int ret;
		connection_table_node* ct_node;
		connection_table_row_t* ctr;
		//loop on the connection
		list_for_each_entry(ct_node, &connection_table_list, list){
				
				ctr = ct_node->ctr;
				if ((ctr->src_ip == ip_header->saddr) && (ctr->dst_ip == ip_header->daddr) && (ctr->src_port == ntohs(tcp_header->source)) && ((ctr->dst_port == ntohs(tcp_header->dest))))
				{
					
					ret = update_state(tcp_header, (ct_node->ctr));
					del_closed_conns();

					//redirect to http proxy, connection with client
					if ((ret == NF_ACCEPT) && (ntohs(tcp_header->dest) == 80))
					{
						change_dest(skb,IN_IP,800);
						return NF_ACCEPT;
					}
					
					//redirect to http proxy, connection with server
					if ((ret == NF_ACCEPT) && (ntohs(tcp_header->source) == 80))
					{
						change_dest(skb,OUT_IP,ctr->local_port);
						if (ctr->local_port == 1)
						{
							change_dest(skb,OUT_IP, ctr->twin->local_port);
						}	
						return NF_ACCEPT;
					}

					//redirect to ftp proxy, connection with client
					if ((ret == NF_ACCEPT) && (ntohs(tcp_header->dest) == 21))
					{
					change_dest(skb,IN_IP,210);
						return NF_ACCEPT;
					}
					
					//redirect to ftp proxy, connection with server
					if ((ret == NF_ACCEPT) && (ntohs(tcp_header->source) == 21))
					{
						change_dest(skb,OUT_IP,ctr->local_port);

						if (ctr->local_port == 1)
						{
							change_dest(skb,OUT_IP, ctr->twin->local_port);

						}	
						return NF_ACCEPT;
					}

					return ret;
				}
		}
		return NF_DROP;   
    }

	//check if this packet is the SYN of the data connection of tcp
	//used for ftp data connection and not adding more tables if a SYN packet is resent.
	if ((packet_protocol == PROT_TCP) && (ntohs(tcp_hdr(skb)->source) == 20))
	{
		connection_table_node* ct_node;
		connection_table_row_t* ctr;
		list_for_each_entry(ct_node, &connection_table_list, list){
				ctr = ct_node->ctr;
				if ((ctr->src_ip == ip_header->saddr) && (ctr->dst_ip == ip_header->daddr) && (ctr->src_port == ntohs(tcp_hdr(skb)->source)) && 
				((ctr->dst_port == ntohs(tcp_hdr(skb)->dest))) && (ctr->state == STATE_SYN_SENT))
				{
					return NF_ACCEPT;
				}
		}
	}

	//deciding direction
	direction_t direction = DIRECTION_OUT;
	if (strcmp(state->in->name, IN_NET_DEVICE_NAME) == 0) {
		direction = DIRECTION_IN;
	} 
    for (i = 0; i < table_size; i++) {
        if (rule_check(skb, &rules_table[i], direction)) {
            update_log(skb, i, rules_table[i].action);
			//add to the dynamic connection table
			if ((packet_protocol == PROT_TCP) && (rules_table[i].action == NF_ACCEPT))
			{
				struct tcphdr *tcp_header = tcp_hdr(skb);
				connection_table_row_t* ctr = kmalloc(sizeof(connection_table_row_t), GFP_KERNEL);
				connection_table_row_t* ctr_twin = kmalloc(sizeof(connection_table_row_t), GFP_KERNEL);

				ctr->src_ip = ip_header->saddr;
				ctr->dst_ip = ip_header->daddr;
				ctr->src_port = ntohs(tcp_header->source);
				ctr->dst_port = ntohs(tcp_header->dest);
				ctr->state = STATE_SYN_SENT;
				ctr->proxy_state = 0;
				ctr->local_port = 0;

				ctr_twin->dst_ip = ip_header->saddr;
				ctr_twin->src_ip = ip_header->daddr;
				ctr_twin->dst_port = ntohs(tcp_header->source);
				ctr_twin->src_port = ntohs(tcp_header->dest);
				ctr_twin->state = STATE_LISTEN;
				ctr_twin->proxy_state = 0;
				ctr_twin->local_port = 0;

				ctr->twin = ctr_twin;
				ctr_twin->twin = ctr;
				if ((ntohs(tcp_header->dest) == 80)){
					ctr->local_port = 1;
					ctr_twin->local_port = 1;
					ctr->proxy_state = STATE_SYN_SENT;
					ctr_twin->proxy_state = STATE_LISTEN;
					change_dest(skb,IN_IP,800);
				}
				if ((ntohs(tcp_header->dest) == 21)){
					ctr->local_port = 1;
					ctr_twin->local_port = 1;
					ctr->proxy_state = STATE_SYN_SENT;
					ctr_twin->proxy_state = STATE_LISTEN;
					change_dest(skb,IN_IP,210);
				}
				add_connection(ctr);
				add_connection(ctr_twin);
			}
			
            return rules_table[i].action;
        }
    }
    update_log(skb, REASON_NO_MATCHING_RULE, NF_DROP);
    return NF_DROP; 
}

//catches the packets that are sent from the proxy to change its source
static unsigned int local_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    
    struct iphdr *ip_header = ip_hdr(skb);
    prot_t packet_protocol = ip_header->protocol;
	//checks if loopback
    if (ip_check(ip_header->daddr,LOOPBACK_IP, LOOPBACK_MASK))
    {
        return NF_ACCEPT;
    }
	
    //the proxy sends only tcp packet so other packets shouldnt be touched.
	if ((packet_protocol != PROT_TCP)){
        return NF_ACCEPT;
    }

    struct tcphdr *tcp_header = tcp_hdr(skb);	
	
	//sent from http proxy
	if(ntohs(tcp_header->source) == 800)
	{
		if (ntohs(tcp_header->dest) != 80)
		{
			unsigned short found_bool = 1;
			connection_table_node* ct_node;
			connection_table_row_t* ctr_temp;
			list_for_each_entry(ct_node, &connection_table_list, list){
				ctr_temp = ct_node->ctr;
				if (found_bool && (ctr_temp->dst_ip == ip_header->daddr) && (ctr_temp->dst_port == ntohs(tcp_header->dest)) && (ctr_temp->src_port == 80))
				{
					change_source(skb,ctr_temp->src_ip,ctr_temp->src_port);
					update_state_local(tcp_hdr(skb),ct_node->ctr->twin);
					found_bool = 0;
					return NF_ACCEPT;
				}
			}

		}
		else {
			printk(KERN_INFO "local hook: ERROR: got for server and expected to user");
			
		}
		return NF_ACCEPT;
	}
	//sent from ftp proxy
	else if (ntohs(tcp_header->source) == 210)
	{
		if (ntohs(tcp_header->dest) != 21)
		{
			unsigned short found_bool = 1;
			connection_table_node* ct_node;
			connection_table_row_t* ctr_temp;
			list_for_each_entry(ct_node, &connection_table_list, list){
				ctr_temp = ct_node->ctr;
				if (found_bool && (ctr_temp->dst_ip == ip_header->daddr) && (ctr_temp->dst_port == ntohs(tcp_header->dest)) && (ctr_temp->src_port == 21))
				{
					change_source(skb,ctr_temp->src_ip,ctr_temp->src_port);
					update_state_local(tcp_hdr(skb),ct_node->ctr->twin);
					found_bool = 0;
					return NF_ACCEPT;
				}
			}

		}
		else {
			printk(KERN_INFO "local hook: ERROR: got for server and expected to user");
			
		}
		return NF_ACCEPT;
	}
	
	else{
		//sent from http proxy
		if (ntohs(tcp_header->dest) == 80)
		{
			unsigned short found_bool = 1;
			connection_table_node* ct_node;
			connection_table_row_t* ctr_temp;
			list_for_each_entry(ct_node, &connection_table_list, list){
				ctr_temp = ct_node->ctr;
				if (found_bool && (ctr_temp->dst_ip == ip_header->daddr) && (ctr_temp->dst_port == 80) && (ctr_temp->local_port == ntohs(tcp_header->source)))
				{
					change_source(skb,ctr_temp->src_ip,ctr_temp->src_port);
					update_state_local(tcp_hdr(skb),ct_node->ctr->twin);
					found_bool = 0;
					return NF_ACCEPT;
				}
			}
			
		}
		//sent from ftp proxy
		else if (ntohs(tcp_header->dest) == 21)
		{
			unsigned short found_bool = 1;
			connection_table_node* ct_node;
			connection_table_row_t* ctr_temp;
			list_for_each_entry(ct_node, &connection_table_list, list){
				ctr_temp = ct_node->ctr;
				if (found_bool && (ctr_temp->dst_ip == ip_header->daddr) && (ctr_temp->dst_port == 21) && (ctr_temp->local_port == ntohs(tcp_header->source)))
				{
					change_source(skb,ctr_temp->src_ip,ctr_temp->src_port);
					update_state_local(tcp_hdr(skb),ct_node->ctr->twin);
					found_bool = 0;
					return NF_ACCEPT;
				}
			}
		}
		//got not from proxy.
		return NF_ACCEPT;
	}
	
	//no reason to get here.
    return NF_ACCEPT; 
}

//init of the module
static int __init mod_init_func(void){
	printk(KERN_INFO "load module");
    
    //create char devices
	major_number = register_chrdev(0, "fw", &fops);
	if (major_number < 0){
		return -1;
	}

	//create sysfs class
	fw_class = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(fw_class))
	{
		unregister_chrdev(major_number, "fw");
		return -1;
	}

	//create sysfs device
	rules_device = device_create(fw_class, NULL, MKDEV(major_number, MINOR_RULES), NULL, DEVICE_NAME_RULES);	
	if (IS_ERR(rules_device))
	{
		class_destroy(fw_class);
		unregister_chrdev(major_number, "fw");
		return -1;
	}

	//create sysfs device
    log_device = device_create(fw_class, NULL, MKDEV(major_number, MINOR_LOG), NULL, DEVICE_NAME_LOG);	
	if (IS_ERR(log_device))
	{
		device_destroy(fw_class, MKDEV(major_number, MINOR_RULES));
		class_destroy(fw_class);
		unregister_chrdev(major_number, "fw");
		return -1;
	}

	//create sysfs device
	conns_device = device_create(fw_class, NULL, MKDEV(major_number, MINOR_CONNS), NULL, DEVICE_NAME_CONN_TAB);	
	if (IS_ERR(conns_device))
	{
		device_destroy(fw_class, MKDEV(major_number, MINOR_RULES));
		device_destroy(fw_class, MKDEV(major_number, MINOR_LOG));
		class_destroy(fw_class);
		unregister_chrdev(major_number, "fw");
		return -1;
	}

	//create sysfs device
	proxy_driver = device_create(fw_class, NULL, MKDEV(major_number, MINOR_PROXY), NULL, "proxy_driver");	
	if (IS_ERR(proxy_driver))
	{
		device_destroy(fw_class, MKDEV(major_number, MINOR_RULES));
		device_destroy(fw_class, MKDEV(major_number, MINOR_LOG));
		device_destroy(fw_class, MKDEV(major_number, MINOR_CONNS));
		class_destroy(fw_class);
		unregister_chrdev(major_number, "fw");
		return -1;
	}

	//create sysfs device
	ftp_driver = device_create(fw_class, NULL, MKDEV(major_number, MINOR_FTP), NULL, "ftp_driver");	
	if (IS_ERR(ftp_driver))
	{
		device_destroy(fw_class, MKDEV(major_number, MINOR_RULES));
		device_destroy(fw_class, MKDEV(major_number, MINOR_LOG));
		device_destroy(fw_class, MKDEV(major_number, MINOR_CONNS));
		device_destroy(fw_class, MKDEV(major_number, MINOR_PROXY));
		class_destroy(fw_class);
		unregister_chrdev(major_number, "fw");
		return -1;
	}


	//create sysfs file attributes	
	if (device_create_file(rules_device, (const struct device_attribute *)&dev_attr_rules.attr))
	{
		device_destroy(fw_class, MKDEV(major_number, MINOR_RULES));
		device_destroy(fw_class, MKDEV(major_number, MINOR_LOG));
		device_destroy(fw_class, MKDEV(major_number, MINOR_CONNS));
		device_destroy(fw_class, MKDEV(major_number, MINOR_PROXY));
		device_destroy(fw_class, MKDEV(major_number, MINOR_FTP));
		class_destroy(fw_class);
		unregister_chrdev(major_number, "fw");
		return -1;
	}
    
	//create sysfs file attributes	
    if (device_create_file(log_device, (const struct device_attribute*) &dev_attr_reset.attr)) {
		device_remove_file(rules_device, (const struct device_attribute*) &dev_attr_rules.attr); 
		device_destroy(fw_class, MKDEV(major_number, MINOR_RULES));
		device_destroy(fw_class, MKDEV(major_number, MINOR_LOG));
		device_destroy(fw_class, MKDEV(major_number, MINOR_CONNS));
		device_destroy(fw_class, MKDEV(major_number, MINOR_PROXY));
		device_destroy(fw_class, MKDEV(major_number, MINOR_FTP));
		class_destroy(fw_class);
		unregister_chrdev(major_number, "fw");
		return -1;
	}

	//create sysfs file attributes	
	if (device_create_file(conns_device, (const struct device_attribute*) &dev_attr_conns.attr)) {
		device_remove_file(rules_device, (const struct device_attribute*) &dev_attr_rules.attr); 
		device_remove_file(log_device, (const struct device_attribute*) &dev_attr_reset.attr); 
		device_destroy(fw_class, MKDEV(major_number, MINOR_RULES));
		device_destroy(fw_class, MKDEV(major_number, MINOR_LOG));
		device_destroy(fw_class, MKDEV(major_number, MINOR_CONNS));
		device_destroy(fw_class, MKDEV(major_number, MINOR_PROXY));
		device_destroy(fw_class, MKDEV(major_number, MINOR_FTP));
		class_destroy(fw_class);
		unregister_chrdev(major_number, "fw");
		return -1;
	}

	//create sysfs file attributes	
	if (device_create_file(proxy_driver, (const struct device_attribute*) &dev_attr_proxy.attr)) {
		device_remove_file(rules_device, (const struct device_attribute*) &dev_attr_rules.attr); 
		device_remove_file(log_device, (const struct device_attribute*) &dev_attr_reset.attr); 
		device_remove_file(conns_device, (const struct device_attribute*) &dev_attr_conns.attr); 
		device_destroy(fw_class, MKDEV(major_number, MINOR_RULES));
		device_destroy(fw_class, MKDEV(major_number, MINOR_LOG));
		device_destroy(fw_class, MKDEV(major_number, MINOR_CONNS));
		device_destroy(fw_class, MKDEV(major_number, MINOR_PROXY));
		device_destroy(fw_class, MKDEV(major_number, MINOR_FTP));
		class_destroy(fw_class);
		unregister_chrdev(major_number, "fw");
		return -1;
	}

	//create sysfs file attributes	
	if (device_create_file(ftp_driver, (const struct device_attribute*) &dev_attr_ftp.attr)) {
		device_remove_file(rules_device, (const struct device_attribute*) &dev_attr_rules.attr); 
		device_remove_file(log_device, (const struct device_attribute*) &dev_attr_reset.attr); 
		device_remove_file(conns_device, (const struct device_attribute*) &dev_attr_conns.attr); 
		device_remove_file(proxy_driver, (const struct device_attribute*) &dev_attr_proxy.attr); 
		device_destroy(fw_class, MKDEV(major_number, MINOR_RULES));
		device_destroy(fw_class, MKDEV(major_number, MINOR_LOG));
		device_destroy(fw_class, MKDEV(major_number, MINOR_CONNS));
		device_destroy(fw_class, MKDEV(major_number, MINOR_PROXY));
		device_destroy(fw_class, MKDEV(major_number, MINOR_FTP));
		class_destroy(fw_class);
		unregister_chrdev(major_number, "fw");
		return -1;
	}

	//create hooks
	hook_fw.hook = (nf_hookfn*)fw_hook;
	hook_fw.pf = PF_INET;
	hook_fw.priority = NF_IP_PRI_FIRST;
	hook_fw.hooknum = NF_INET_PRE_ROUTING;
	if(nf_register_net_hook(&init_net,&hook_fw) < 0){
        device_remove_file(log_device, (const struct device_attribute*) &dev_attr_reset.attr); 
	    device_remove_file(rules_device, (const struct device_attribute*) &dev_attr_rules.attr); 
		device_remove_file(conns_device, (const struct device_attribute*) &dev_attr_conns.attr); 
		device_remove_file(proxy_driver, (const struct device_attribute*) &dev_attr_proxy.attr); 
		device_remove_file(ftp_driver, (const struct device_attribute*) &dev_attr_ftp.attr); 
	    device_destroy(fw_class,  MKDEV(major_number, MINOR_RULES));
	    device_destroy(fw_class,  MKDEV(major_number, MINOR_LOG));
		device_destroy(fw_class, MKDEV(major_number, MINOR_CONNS));
		device_destroy(fw_class, MKDEV(major_number, MINOR_PROXY));
		device_destroy(fw_class, MKDEV(major_number, MINOR_FTP));
	    class_destroy(fw_class);
	    unregister_chrdev(major_number, "fw");
    }
	hook_local.hook = (nf_hookfn*)local_hook;
	hook_local.pf = PF_INET;
	hook_local.priority = NF_IP_PRI_FIRST;
	hook_local.hooknum = NF_INET_LOCAL_OUT;
	if(nf_register_net_hook(&init_net,&hook_local) < 0){
		nf_unregister_net_hook(&init_net,&hook_fw);
        device_remove_file(log_device, (const struct device_attribute*) &dev_attr_reset.attr); 
	    device_remove_file(rules_device, (const struct device_attribute*) &dev_attr_rules.attr); 
		device_remove_file(conns_device, (const struct device_attribute*) &dev_attr_conns.attr); 
		device_remove_file(proxy_driver, (const struct device_attribute*) &dev_attr_proxy.attr); 
		device_remove_file(ftp_driver, (const struct device_attribute*) &dev_attr_ftp.attr); 
	    device_destroy(fw_class,  MKDEV(major_number, MINOR_RULES));
	    device_destroy(fw_class,  MKDEV(major_number, MINOR_LOG));
		device_destroy(fw_class, MKDEV(major_number, MINOR_CONNS));
		device_destroy(fw_class, MKDEV(major_number, MINOR_PROXY));
		device_destroy(fw_class, MKDEV(major_number, MINOR_FTP));
	    class_destroy(fw_class);
	    unregister_chrdev(major_number, "fw");
    }


    memset(rules_table, 0, MAX_RULES * sizeof(rule_t));


    return 0;
}

//exit of the module.
static void __exit mod_exit_func(void){
	nf_unregister_net_hook(&init_net,&hook_fw);
	nf_unregister_net_hook(&init_net,&hook_local);
	device_remove_file(log_device, (const struct device_attribute*) &dev_attr_reset.attr); 
	device_remove_file(rules_device, (const struct device_attribute*) &dev_attr_rules.attr); 
	device_remove_file(conns_device, (const struct device_attribute*) &dev_attr_conns.attr); 
	device_remove_file(proxy_driver, (const struct device_attribute*) &dev_attr_proxy.attr); 
	device_remove_file(ftp_driver, (const struct device_attribute*) &dev_attr_ftp.attr); 
	device_destroy(fw_class,  MKDEV(major_number, MINOR_RULES));
	device_destroy(fw_class,  MKDEV(major_number, MINOR_LOG));
	device_destroy(fw_class, MKDEV(major_number, MINOR_CONNS));
	device_destroy(fw_class, MKDEV(major_number, MINOR_PROXY));
	device_destroy(fw_class, MKDEV(major_number, MINOR_FTP));
	class_destroy(fw_class);
	unregister_chrdev(major_number, "fw");

    free_log_list();
	free_connection_table_list();
}

module_init(mod_init_func);
module_exit(mod_exit_func);