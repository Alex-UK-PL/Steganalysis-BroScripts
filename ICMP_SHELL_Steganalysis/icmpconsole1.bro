## ICMPStegDetect.bro
## Version : 0.6
## Author : Alexander Drabek, drabek.a@o2.pl
## https://github.com/Alex-UK-PL/Steganalysis-BroScripts
## 
## !CAUTION! The packet level analysis is performed!    !CAUTION!
## !CAUTION! Author is not responsible losses which,    !CAUTION!
## !CAUTION!  are caused by using provided script.      !CAUTION! 
## !CAUTION! This script may result in false positives! !CAUTION!
##

module stegicmp;

 
export {
    redef enum Log::ID += { LOG };
    global Payload_CON_Table: table [count] of string ;# &default=0;
    global AlexINV_len: table [count] of string ;# &default=0;
    global Unique_icmpSET: set [string];
    global STEG_SET: set [string];
    
    type Info: record 
    {
      ts: time &log;
      Connection_UID_value: string &log;
      Sample_IP_Payload_Lenght: count &log;
    };
}

event bro_init() 
{
 Log::create_stream(LOG, [$columns=Info]);
}

#    event new_packet(c: connection, p: pkt_hdr)
#     {
#    Could do a check on a p$icmp!="" - type of record with count in it
#   if ( is_icmp_port(c$id$resp_p) || is_icmp_port(c$id$orig_p) ){}
#     }

#Below collection within two tables reduce the number of false positives 
#however the root cause of sorting via icmp length rather then connID is not solved!!!
#False positives due to various apps using ping may occur.

event icmp_sent(c: connection, icmp: icmp_conn)
	{
    if (Payload_CON_Table[icmp$len] !=c$uid) AlexINV_len[icmp$len] =c$uid;
    Payload_CON_Table[icmp$len] = c$uid ;
    print fmt("PART OF connection : ID : %s ",c$uid );
	}

event icmp_echo_request(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string)
	{
    if (Payload_CON_Table[|payload|] !=c$uid) AlexINV_len[|payload|] =c$uid;
    Payload_CON_Table[|payload|] = c$uid ;
    print fmt("PART OF connection : ID : %s ",c$uid );
	}

event icmp_echo_reply(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string)
	{
    if (Payload_CON_Table[|payload|] !=c$uid) AlexINV_len[|payload|] =c$uid;
    Payload_CON_Table[|payload|] = c$uid ;
    print fmt("PART OF connection : ID : %s ",c$uid );
  
	}

event icmp_error_message(c: connection, icmp: icmp_conn, code: count, context: icmp_context)
	{
	
    if (Payload_CON_Table[icmp$len] !=c$uid) AlexINV_len[icmp$len] =c$uid;
   Payload_CON_Table[icmp$len] = c$uid ;
   print fmt("PART OF connection : ID : %s ",c$uid );
	}

event icmp_neighbor_advertisement(c: connection, icmp: icmp_conn, router: bool, solicited: bool, override: bool, tgt: addr, options: icmp6_nd_options)
	{
    if (Payload_CON_Table[icmp$len] !=c$uid) AlexINV_len[icmp$len] =c$uid;
   Payload_CON_Table[icmp$len] = c$uid ;
   print fmt("PART OF connection : ID : %s ",c$uid );
   	}

event icmp_neighbor_solicitation(c: connection, icmp: icmp_conn, tgt: addr, options: icmp6_nd_options)
	{
    if (Payload_CON_Table[icmp$len] !=c$uid) AlexINV_len[icmp$len] =c$uid;
   Payload_CON_Table[icmp$len] = c$uid ;
   print fmt("PART OF connection : ID : %s ",c$uid );
	}

event icmp_packet_too_big(c: connection, icmp: icmp_conn, code: count, context: icmp_context)
	{
    if (Payload_CON_Table[icmp$len] !=c$uid) AlexINV_len[icmp$len] =c$uid;
   Payload_CON_Table[icmp$len] = c$uid ;
   print fmt("PART OF connection : ID : %s ",c$uid );
  
	}

event icmp_parameter_problem(c: connection, icmp: icmp_conn, code: count, context: icmp_context)
	{
    if (Payload_CON_Table[icmp$len] !=c$uid) AlexINV_len[icmp$len] =c$uid;
   Payload_CON_Table[icmp$len] = c$uid ;
   print fmt("PART OF connection : ID : %s ",c$uid );
	}

event icmp_redirect(c: connection, icmp: icmp_conn, tgt: addr, dest: addr, options: icmp6_nd_options)
	{
   if (Payload_CON_Table[icmp$len] !=c$uid) AlexINV_len[icmp$len] =c$uid;
   Payload_CON_Table[icmp$len] = c$uid ;
   print fmt("PART OF connection : ID : %s ",c$uid );
	}

event icmp_router_advertisement(c: connection, icmp: icmp_conn, cur_hop_limit: count, managed: bool, other: bool, home_agent: bool, pref: count, proxy: bool, rsv: count, router_lifetime: interval, reachable_time: interval, retrans_timer: interval, options: icmp6_nd_options)
	{
    if (Payload_CON_Table[icmp$len] !=c$uid) AlexINV_len[icmp$len] =c$uid;
   Payload_CON_Table[icmp$len] = c$uid;
   print fmt("PART OF connection : ID : %s ",c$uid );
	}

event icmp_router_solicitation(c: connection, icmp: icmp_conn, options: icmp6_nd_options)
	{
    if (Payload_CON_Table[icmp$len] !=c$uid) AlexINV_len[icmp$len] =c$uid;
   Payload_CON_Table[icmp$len] = c$uid;
   print fmt("PART OF connection : ID : %s ",c$uid );
	}

event icmp_time_exceeded(c: connection, icmp: icmp_conn, code: count, context: icmp_context)
	{
    if (Payload_CON_Table[icmp$len] !=c$uid) AlexINV_len[icmp$len] =c$uid;
   Payload_CON_Table[icmp$len] = c$uid;
   print fmt("PART OF connection : ID : %s ",c$uid );
	}

event icmp_unreachable(c: connection, icmp: icmp_conn, code: count, context: icmp_context)
	{
    if (Payload_CON_Table[icmp$len] !=c$uid) AlexINV_len[icmp$len] =c$uid;
    Payload_CON_Table[icmp$len] = c$uid;
    print fmt("PART OF connection : ID : %s ",c$uid );
	}

event bro_done()
{
 #TODO : Move the exec into other event - con state remove and remove processed entries   
  for (lengICMP in Payload_CON_Table)
  {
      if (Payload_CON_Table[lengICMP] in  Unique_icmpSET)
        { 
         #print stego or/AND save stego ID
         add STEG_SET[Payload_CON_Table[lengICMP]];
        }
      if (Payload_CON_Table[lengICMP] !in  Unique_icmpSET)
        {
          add Unique_icmpSET[Payload_CON_Table[lengICMP]]; 
          local mes1 = [$ts = network_time(),$Connection_UID_value=Payload_CON_Table[lengICMP], $Sample_IP_Payload_Lenght = lengICMP];
          Log::write(LOG, mes1);  
        } 
   } 
  
  for (i in STEG_SET) #All unique icmp connections ids
   { 
     print fmt(" Steg Set entry%s",i);
   }

}