/************************************************************************/

#include "ncrack.h"
#include "nsock.h"
#include "NcrackOps.h"
#include "Service.h"
#include "modules.h"

#define IMAP_TIMEOUT 20000 //Here

extern NcrackOps o;

extern void ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_module_end(nsock_pool nsp, void *mydata);

static int imap_loop_read(nsock_pool nsp, Connection *con);

enum states { IMAP_INIT, IMAP_USER, IMAP_FINI };

static int
imap_loop_read(nsock_pool nsp, Connection *con)
{

	if (con->inbuf == NULL || con->inbuf->get_len() < 3) {
		nsock_read(nsp, con->niod, ncrack_read_handler, IMAP_TIMEOUT, con);
		return -1;
	}

	if (memsearch((const char *)con->inbuf->get_dataptr(), "ERR",con->inbuf->get_len()))
		{
			return 2;
		}
	//OK Dovecot ready.\r\n
	if (!(memsearch((const char *)con->inbuf->get_dataptr(),"OK\r\n",con->inbuf->get_len()))) {
			return 1;
		}
			return 0;
}



void
ncrack_imap(nsock_pool nsp, Connection *con)
{
	int ret;
	nsock_iod nsi = con->niod;
	Service *serv = con->service;
	
	switch(con->state)
	{
		case IMAP_INIT:
		
			if (!con->login_attempts) {

				if((imap_loop_read(nsp, con)) < 0) {
						break;
				}
				
				if (ret == 1) {

					if (o.debugging > 6){
					error("%s Not imap or service was shutdown\n", serv->HostInfo());
					return ncrack_module_end(nsp, con);
				}
			}
		}
		
			con->state = IMAP_USER;

			delete con->inbuf;
			con->inbuf = NULL;

			if (con->outbuf)
				delete con->outbuf;
			con->outbuf = new Buf();
			con->outbuf->snprintf(12 + strlen(con->user) + strlen(con->pass), "01 LOGIN %s %s\r\n", con->user, con->pass);

			nsock_write(nsp, nsi, ncrack_write_handler, IMAP_TIMEOUT, con, (const char *)con->outbuf->
				get_dataptr(), con->outbuf->get_len());
			break;
		
		case IMAP_USER:
			
			if ((imap_loop_read(nsp, con)) < 0)
				break;

			if (ret == 2) {
				if (o.debugging > 6) {
					error("%s Unknown user: %s\n", serv->HostInfo(), con->user);
					return ncrack_module_end(nsp,con);
							}

			if (ret == 1) {
				if (o.debugging > 6) {
					error("%s Unkown imap error for USER\n", serv->HostInfo());
					return ncrack_module_end(nsp,con);
				}
			}

			con->state = IMAP_FINI;

			delete con->inbuf;
			con->inbuf = NULL;

			if (con->outbuf)
				delete con->outbuf;
			con->outbuf = new Buf();
			con->outbuf->snprintf(12 + strlen(con->user) + strlen(con->pass), "01 LOGIN %s %s\r\n",con->user, con->pass);

			nsock_write(nsp, nsi, ncrack_write_handler, IMAP_TIMEOUT, con,
					(const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
			break;

		case IMAP_FINI:

			if ((ret = imap_loop_read(nsp, con)) < 0)
				break;
			
			if(ret == 0) 
				con->auth_success = true;

			con->state = IMAP_INIT;

			delete con->inbuf;
			con->inbuf = NULL;

			return ncrack_module_end(nsp, con);
		}
}}
