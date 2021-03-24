#ifndef __HTTP_H__
#define __HTTP_H__

#include "main.h"

struct http_request {
    unsigned char *method;
    unsigned char *url;
    unsigned char *version;
};

extern int detec_http(struct prt_info *pi);


#endif /* __HTTP_H__ */