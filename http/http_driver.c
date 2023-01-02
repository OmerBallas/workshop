#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdio.h>
#include <fcntl.h>  
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


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
	unsigned short	local_port;
	state_t state;
	struct connection_table_row_ts* twin;
} connection_table_row_t;


//send the local port to the fw module
static PyObject* fit(PyObject* self, PyObject* args){
        connection_table_row_t ctr;
        int src_ip;
        int dst_ip;
        int src_port;
        int dst_port;
        int local_port;


        if (!PyArg_ParseTuple(args, "iiiii",&src_ip, &src_port, &dst_ip, &dst_port, &local_port))
        {
                return NULL;
        }
        ctr.src_ip = src_ip;
        ctr.dst_ip = dst_ip;
        ctr.src_port = src_port;
        ctr.dst_port = dst_port;
        ctr.local_port = local_port;
        ctr.state = 0;
        ctr.twin = 0;

        int fd = open("/sys/class/fw/http_driver/http", O_WRONLY);
        if (fd < 0){
                printf("failed to open\n");
                close(fd);
                return -1;
        }
        if (write(fd,&ctr, sizeof(connection_table_row_t)) < 0)
        {
                printf("failed write\n");
                printf("%s\n", strerror(errno));
                close(fd);
                return -1;
        }
        close(fd);
        return PyLong_FromLong(1);
}

//read the ip which belongs to the server
static PyObject* fit2(PyObject* self, PyObject* args){
        connection_table_row_t ctr;
        connection_table_row_t table[4];
        printf("size of ctr: %d\n", sizeof(ctr));
        int ret;
        int src_ip;
        int src_port;
        int fd;
        PyObject* ret_py;
        fd = open("/sys/class/fw/conns/conns", O_RDONLY);
        if (fd < 0){
                printf("failed to open\n");
                return -1;
        }
        if (!PyArg_ParseTuple(args, "ii", &src_ip, &src_port))
        {
                return NULL;
        }
        if ((ret = read(fd, table, 4 * sizeof(connection_table_row_t))) < 0){
                printf("failed to read\n");
                printf("ret: %d", ret);
                close(fd);
                return -1;
        }
        printf("ret: %d\n", ret);
        printf("src ip: %d\n",&src_ip);
        printf("src port: %d\n",src_port);
        for(int i = 0; i < ret / sizeof(connection_table_row_t); i++){
                if ((table[i].src_ip == src_ip) && (table[i].src_port == src_port) && (table[i].dst_port == 80))
                {
                        ret_py = PyLong_FromLong(table[i].dst_ip);
                        close(fd);
                        return ret_py;
                }
                
        }
        printf("didnt find fit ctr\n");
        return -1;
}













/*
c python API
*/
static PyMethodDef _methods[] = {
        {"fit", (PyCFunction)fit, METH_VARARGS, PyDoc_STR("fit")},
        {"fit2", (PyCFunction)fit2, METH_VARARGS, PyDoc_STR("fit2")},
        {NULL, NULL, 0, NULL}   /* sentinel */
};

/*
c python API
*/
static struct PyModuleDef _moduledef = {
        PyModuleDef_HEAD_INIT,
        "http_driver",
        NULL,
        -1,
        _methods
};
/*
c python API
*/
PyMODINIT_FUNC PyInit_http_driver(void)
{
    return PyModule_Create(&_moduledef);
}