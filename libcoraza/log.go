package main

/*
typedef void (*coraza_log_cb) (const void *);

typedef void (*coraza_log_closure) (void *, const char *);

void send_log_to_cb(coraza_log_cb cb, const char *msg){
	cb(msg);
}


void send_log_to_closure(coraza_log_closure cb, void *ctx, const char *msg){
	cb(ctx, msg);
}
*/
import "C"
