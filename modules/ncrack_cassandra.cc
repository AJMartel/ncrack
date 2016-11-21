/***************************************************************************
 * ncrack_imap.cc -- ncrack module for the imap protocol                   *
 * created by barrend                                                      *
 *                                                                         *
 ***********************important nmap license terms************************
 *                                                                         *
 * the nmap security scanner is (c) 1996-2016 insecure.com llc. nmap is    *
 * also a registered trademark of insecure.com llc.  this program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * gnu general public license as published by the free software            *
 * foundation; version 2 ("gpl"), but only with all of the clarifications  *
 * and exceptions described herein.  this guarantees your right to use,    *
 * modify, and redistribute this software under certain conditions.  if    *
 * you wish to embed nmap technology into proprietary software, we sell    *
 * alternative licenses (contact sales@nmap.com).  dozens of software      *
 * vendors already license nmap technology such as host discovery, port    *
 * scanning, os detection, version detection, and the nmap scripting       *
 * engine.                                                                 *
 *                                                                         *
 * note that the gpl places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  to avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  for example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("covered software"):                                                   *
 *                                                                         *
 * o integrates source code from covered software.                         *
 *                                                                         *
 * o reads or includes copyrighted data files, such as nmap's nmap-os-db   *
 * or nmap-service-probes.                                                 *
 *                                                                         *
 * o is designed specifically to execute covered software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o includes covered software in a proprietary executable installer.  the *
 * installers produced by installshield are an example of this.  including *
 * nmap with other software in compressed or archival form does not        *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  for the    *
 * purposes of this license, an installer is considered to include covered *
 * software even if it actually retrieves a copy of covered software from  *
 * another source during runtime (such as by downloading it from the       *
 * internet).                                                              *
 *                                                                         *
 * o links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * this list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  other people may interpret *
 * the plain gpl differently, so we consider this a special exception to   *
 * the gpl that we apply to covered software.  works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the gpl section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * as another special exception to the gpl terms, insecure.com llc grants  *
 * permission to link the code of this program with any version of the     *
 * openssl library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/openssl.txt file, and distribute   *
 * linked combinations including the two.                                  *
 *                                                                         *
 * any redistribution of covered software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all gpl rules and restrictions.  for example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  all gpl references to "this license", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * because this license imposes special exceptions to the gpl, covered     *
 * work may not be combined (even as part of a larger work) with plain gpl *
 * software.  the terms, conditions, and exceptions of this license must   *
 * be included as well.  this license is incompatible with some other open *
 * source licenses as well.  in some cases we can relicense portions of    *
 * nmap or grant special permissions to use it in other open source        *
 * software.  please contact fyodor@nmap.org with any such requests.       *
 * similarly, we don't incorporate incompatible open source software into  *
 * covered software without special permission from the copyright holders. *
 *                                                                         *
 * if you have any questions about the licensing restrictions on using     *
 * nmap in other works, are happy to help.  as mentioned above, we also    *
 * offer alternative license to integrate nmap into proprietary            *
 * applications and appliances.  these contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates.  they also fund the      *
 * continued development of nmap.  please email sales@nmap.com for further *
 * information.                                                            *
 *                                                                         *
 * if you have received a written license agreement or contract for        *
 * covered software stating terms other than these, you may choose to use  *
 * and redistribute covered software under those terms instead of these.   *
 *                                                                         *
 * source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * this also allows you to audit the software for security holes.          *
 *                                                                         *
 * source code also allows you to port nmap to new platforms, fix bugs,    *
 * and add new features.  you are highly encouraged to send your changes   *
 * to the dev@nmap.org mailing list for possible incorporation into the    *
 * main distribution.  by sending these changes to fyodor or one of the    *
 * insecure.org development mailing lists, or checking them into the nmap  *
 * source code repository, it is understood (unless you specify otherwise) *
 * that you are offering the nmap project (insecure.com llc) the           *
 * unlimited, non-exclusive right to reuse, modify, and relicense the      *
 * code.  nmap will always be available open source, but this is important *
 * because the inability to relicense code has caused devastating problems *
 * for other free software projects (such as kde and nasm).  we also       *
 * occasionally relicense the code to third parties as discussed above.    *
 * if you wish to specify special license conditions of your               *
 * contributions, just say so when you send them.                          *
 *                                                                         *
 * this program is distributed in the hope that it will be useful, but     *
 * without any warranty; without even the implied warranty of              *
 * merchantability or fitness for a particular purpose.  see the nmap      *
 * license file for more details (it's in a copying file included with     *
 * nmap, and also available from https://svn.nmap.org/nmap/copying)        *
 *                                                                         *
 ***************************************************************************/

#include "ncrack.h"
#include "nsock.h"
#include "NcrackOps.h"
#include "Service.h"
#include "modules.h"

#define cass_timeout 20000 //here

extern NcrackOps o;

extern void ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_module_end(nsock_pool nsp, void *mydata);

/*static int cass_loop_read(nsock_pool nsp, Connection *con);*/

enum states { CASS_INIT, CASS_USER };


static int
cass_loop_read(nsock_pool nsp, Connection *con)
{

  if ((con->inbuf == NULL) || !(memsearch((const char *)con->inbuf->get_dataptr(),"\r\n",con->inbuf->get_len()))) {
    nsock_read(nsp, con->niod, ncrack_read_handler, cass_timeout, con);
    return -1;
    printf("step1");
  }

  if (memsearch((const char *)con->inbuf->get_dataptr(),"Username and/or password are incorrect",con->inbuf->get_len()))
    return 1;
    printf("step2");

  return 0;
}



void
ncrack_cassandra(nsock_pool nsp, Connection *con)
{
  int ret;
  nsock_iod nsi = con->niod;

  switch(con->state)
  {
    case CASS_INIT:

    /* if (!con->login_attempts) {
      if ((cass_loop_read(nsp, con)) = 0) {
        break;
      }
    }*/

    con->state = CASS_USER;

    delete con->inbuf;
    con->inbuf = NULL;

    if (con->outbuf)
      delete con->outbuf;
    con->outbuf = new Buf();
    con->outbuf-snprintf(65 + strlen(con->user) + strlen(con->pass) , con->user, con->pass);

    nsock_write(nsp, nsi, ncrack_write_handler, cass_timeout, con, (const char *)con->outbuf->
        get_dataptr(), con->outbuf->get_len());
    break;

  case CASS_USER: 

    if ((ret = cass_loop_read(nsp, con)) < 0)
      break;

    if (ret == 0)
      con->auth_success = true;

    con->state = CASS_INIT;

    return ncrack_module_end(nsp, con);
  }
}
