#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdio.h>
#include <fcntl.h>  
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>




typedef enum {
	ACK_NO 		= 0x01,
	ACK_YES 	= 0x02,
	ACK_ANY 	= ACK_NO | ACK_YES,
} ack_t;

typedef enum {
	DIRECTION_IN 	= 0x01,
	DIRECTION_OUT 	= 0x02,
	DIRECTION_ANY 	= DIRECTION_IN | DIRECTION_OUT,
} direction_t;

typedef enum {
	REASON_FW_INACTIVE           = -1,
	REASON_NO_MATCHING_RULE      = -2,
	REASON_XMAS_PACKET           = -4,
	REASON_ILLEGAL_VALUE         = -6,
} reason_t;

// rule base
typedef struct {
	char rule_name[20];			// names will be no longer than 20 chars
	direction_t direction;
	unsigned int	    src_ip;
	unsigned int	    src_prefix_mask; 	// e.g., 255.255.255.0 as int in the local endianness
	unsigned char    src_prefix_size; 	// valid values: 0-32, e.g., /24 for the example above
								// (the field is redundant - easier to print)
	unsigned int	    dst_ip;
	unsigned int	    dst_prefix_mask; 	// as above
	unsigned char    dst_prefix_size; 	// as above	
	unsigned short	src_port; 			// number of port or 0 for any or port 1023 for any port number > 1023  
	unsigned short	dst_port; 			// number of port or 0 for any or port 1023 for any port number > 1023 
	unsigned char	protocol; 			// values from: prot_t
	ack_t	ack; 				// values from: ack_t
	unsigned char	action;   			// valid values: NF_ACCEPT, NF_DROP
} rule_t;

typedef struct {
	unsigned long  	timestamp;     	// time of creation/update
	unsigned char  	protocol;     	// values from: prot_t
	unsigned char  	action;       	// valid values: NF_ACCEPT, NF_DROP
	unsigned int   	src_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	unsigned int	dst_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	unsigned short 	src_port;	  	// if you use this struct in userspace, change the type to unsigned short
	unsigned short 	dst_port;	  	// if you use this struct in userspace, change the type to unsigned short
	reason_t     	reason;       	// rule#index, or values from: reason_t
	unsigned int   	count;        	// counts this line's hits
} log_row_t;

typedef enum {
	STATE_ERROR = -1,
	STATE_LISTEN = 0,
	STATE_SYN_SENT = 1,
	STATE_SYN_RECIVED = 2,
	STATE_CLOSE_WAIT = 3,
	STATE_LAST_ACK = 4,
	STATE_FIN_WAIT_1 = 5,
	STATE_FIN_WAIT_2 = 6,
	STATE_CLOSED = 7,
	STATE_ESTABLISHED_TCP = 8,
	STATE_ESTABLISHED_FTP_CON = 9,
	STATE_ESTABLISHED_FTP_DATA = 10,
	STATE_ESTABLISHED_HTTP = 11,
} state_t;

typedef struct connection_table_row_ts
{
	unsigned int	src_ip;
	unsigned int	dst_ip;
	unsigned short	src_port; 
	unsigned short	dst_port; 
	unsigned short 	local_port;
	state_t state;
    state_t proxy_state;
	struct connection_table_row_ts* twin;
} connection_table_row_t;

rule_t rule[50];
int num_of_rules = 0;


unsigned int prefix_calc(int size){
    
    int count = 0;
    unsigned int ret = 0;
    while ((32 >= size) && (size > 0))
    {
        if(size >= 8){
            ret += ((1 << 8)-1) << 8 * count;
        }
        else{
            ret += ((1 << 8) - (1<< (8-size))) << count * 8;
        }
        count++;
        size -= 8;
        
    }
    return ret;
    
}

//read logs
static PyObject* fit4(PyObject* self, PyObject* args){
    PyObject* ret_py;
    PyObject* tmp;
    log_row_t current;
    unsigned long out_timestamp;
    unsigned short out_protocol;
    unsigned short out_action;
    unsigned int out_src_ip;
    unsigned short out_src_port;
    unsigned int out_dst_ip;
    unsigned short out_dst_port;
    int out_reason;
    unsigned int out_count;
    int fd;
    int ret = 1;
    fd = open("/dev/firewall_log",O_RDONLY);
    printf("fd2: %d\n",fd);
    if (fd < 0){
        printf("failed to open\n");
        return -1;
    }
    ret_py = PyList_New(0);
    while (ret > 0)
    {
        ret = read(fd, &current, 1 * sizeof(log_row_t));
        if (ret  < 0){
            printf("failed to read\n");
            return -1;
        }
        else if (ret == 0)
        {
            return ret_py;
        }
        
        out_timestamp = current.timestamp;
        out_protocol = current.protocol;
        out_action = current.action;
        out_src_ip = current.src_ip;
        out_src_port = current.src_port;
        out_dst_ip = current.dst_ip;
        out_dst_port = current.dst_port;
        out_reason = current.reason;
        out_count = current.count;
        tmp = Py_BuildValue("[k,H,H,I,H,I,H,i,I]", out_timestamp, out_protocol, out_action, out_src_ip, out_src_port, out_dst_ip, out_dst_port, out_reason,out_count);
        PyList_Append(ret_py,tmp);
    }
    close(fd);
    return ret_py;

    
    
}

//build rule table
static PyObject* fit2(PyObject* self, PyObject* args){
    PyObject* input;
    PyObject* tmp;
    const char* inp_name;
    unsigned short inp_direction;
    unsigned int inp_src_ip;
    unsigned short inp_src_port;
    unsigned int inp_dst_ip;
    unsigned short inp_dst_port;
    unsigned char inp_src_prefix_size;
    unsigned char inp_dst_prefix_size;
    unsigned char inp_protocol;
    unsigned short inp_ack;
    unsigned char inp_action;

   if(!PyArg_ParseTuple(args, "sHIBIBHHBHB", &inp_name, &inp_direction, &inp_src_ip, &inp_src_prefix_size,&inp_dst_ip,
            &inp_dst_prefix_size,&inp_src_port, &inp_dst_port, &inp_protocol,&inp_ack,&inp_action)){
            return NULL;
        }
    strcpy(rule[num_of_rules].rule_name, inp_name);
    rule[num_of_rules].src_ip = inp_src_ip;
    rule[num_of_rules].dst_ip = inp_dst_ip;
    rule[num_of_rules].src_port = inp_src_port;
    rule[num_of_rules].dst_port = inp_dst_port;
    rule[num_of_rules].direction = inp_direction; 
    rule[num_of_rules].src_prefix_mask = prefix_calc(inp_src_prefix_size);
    rule[num_of_rules].src_prefix_size = inp_src_prefix_size;
    rule[num_of_rules].dst_prefix_mask = prefix_calc(inp_dst_prefix_size);
    rule[num_of_rules].dst_prefix_size = inp_dst_prefix_size;
    rule[num_of_rules].action = inp_action;
    rule[num_of_rules].protocol = inp_protocol;
    rule[num_of_rules].ack = inp_ack;
    num_of_rules += 1;
    
    return PyLong_FromLong(1);
}

//write rule table
static PyObject* fit3(PyObject* self, PyObject* args){
    int ret;
    int fd = open("/sys/class/fw/rules/rules", O_RDWR);
    if (fd < 0){
        printf("failed to open\n");
        return -1;
    }
    
    if ((ret = write(fd,rule, num_of_rules *sizeof(rule_t))) < 0)
    {
        printf("failed to write\n");
        return -1;
    }
    close(fd);
    return PyLong_FromLong(1);
}

//read rule
static PyObject* fit(PyObject* self, PyObject* args){
    PyObject* tmp;
    PyObject* ret_py;
    const char* out_name;
    unsigned short out_direction;
    unsigned int out_src_ip;
    unsigned short out_src_port;
    unsigned int out_dst_ip;
    unsigned short out_dst_port;
    unsigned char out_src_prefix_size;
    unsigned char out_dst_prefix_size;
    unsigned char out_protocol;
    unsigned short out_ack;
    unsigned char out_action;
    int fd;
    int ret;
    fd = open("/sys/class/fw/rules/rules", O_RDWR);
    if (fd < 0){
        printf("failed to open\n");
        return -1;
    }


    rule_t r[50];
    if ((ret = read(fd, r, 50 * sizeof(rule_t))) < 0){
        printf("failed to read\n");
        return -1;
    }
    ret_py = PyList_New(0);
    for(int i = 0; i < ret / sizeof(rule_t); i++){
        out_name = r[i].rule_name;
        out_direction = r[i].direction;
        out_src_ip = r[i].src_ip;
        out_src_port = r[i].src_port;
        out_src_prefix_size = r[i].src_prefix_size;
        out_dst_ip = r[i].dst_ip;
        out_dst_port = r[i].dst_port;
        out_dst_prefix_size = r[i].dst_prefix_size;
        out_protocol = r[i].protocol;
        out_action = r[i].action;
        out_ack = r[i].ack;
        tmp = Py_BuildValue("[s,H,I,B,I,B,B,H,H,H,B]", out_name,out_direction, out_src_ip, out_src_prefix_size,out_dst_ip, out_dst_prefix_size,out_protocol, out_src_port, out_dst_port,out_ack,out_action);
        PyList_Append(ret_py,tmp);
    }
    return ret_py;




}

//reset log
static PyObject* fit5(PyObject* self, PyObject* args){
    int fd;
    int ret;
    fd = open("/sys/class/fw/firewall_log/reset", O_WRONLY);
    if (fd < 0){
        printf("failed to open\n");
        return -1;
    }
    if ((ret = write(fd,&fd, sizeof(int))) < 0)
    {
        printf("failed to write\n");
        return -1;
    }
    close(fd);
    return PyLong_FromLong(1);
    
}

//reset log table for load
static PyObject* fit6(PyObject* self, PyObject* args){
    num_of_rules = 0;
    return PyLong_FromLong(1);
    
}

//read conns
static PyObject* fit7(PyObject* self, PyObject* args){
    PyObject* tmp;
    PyObject* ret_py;
    unsigned int src_ip;
    unsigned short src_port;
    unsigned int dst_ip;
    unsigned short dst_port;
    short state;
    int fd;
    int ret;
    fd = open("/sys/class/fw/conns/conns", O_RDONLY);
    if (fd < 0){
        printf("failed to open\n");
        return -1;
    }


    connection_table_row_t ct[4096];
    if ((ret = read(fd, ct, 4096 * sizeof(connection_table_row_t))) < 0){
        printf("failed to read\n");
        return -1;
    }
    ret_py = PyList_New(0);
    for(int i = 0; i < ret / sizeof(connection_table_row_t); i++){
        src_ip = ct[i].src_ip;
        src_port = ct[i].src_port;
        dst_ip = ct[i].dst_ip;
        dst_port = ct[i].dst_port;
        state = ct[i].state;
        tmp = Py_BuildValue("[I,H,I,H,h]",src_ip,src_port,dst_ip,dst_port,state);
        PyList_Append(ret_py,tmp);
    }
    return ret_py;




}



/*
c python API
*/
static PyMethodDef _methods[] = {
        {"fit", (PyCFunction)fit, METH_VARARGS, PyDoc_STR("fit")},
        {"fit2", (PyCFunction)fit2, METH_VARARGS, PyDoc_STR("fit2")},
        {"fit3", (PyCFunction)fit3, METH_VARARGS, PyDoc_STR("fit3")},
        {"fit4", (PyCFunction)fit4, METH_VARARGS, PyDoc_STR("fit4")},
        {"fit5", (PyCFunction)fit5, METH_VARARGS, PyDoc_STR("fit5")},
        {"fit6", (PyCFunction)fit6, METH_VARARGS, PyDoc_STR("fit6")},
        {"fit7", (PyCFunction)fit7, METH_VARARGS, PyDoc_STR("fit7")},
        {NULL, NULL, 0, NULL}   /* sentinel */
};

/*
c python API
*/
static struct PyModuleDef _moduledef = {
        PyModuleDef_HEAD_INIT,
        "userp",
        NULL,
        -1,
        _methods
};
/*
c python API
*/
PyMODINIT_FUNC PyInit_userp(void)
{
    return PyModule_Create(&_moduledef);
}