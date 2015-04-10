module ipid;

export {
    redef enum Log::ID += { LOG };
    redef enum Notice::Type += { IPIDdetected };

    global testConState : string = "";
    global testConID: string = "";
    global REJ_count: count = 0;
}

event connection_state_remove(c: connection)
{
 
 testConState="other";
  if (c$conn$conn_state == "REJ")  
  {
   testConState="REJ";
  }
}

event new_packet(c: connection, p: pkt_hdr)
{
 local testIPID=0;
 if (is_tcp_port(c$id$resp_p) || is_tcp_port(c$id$orig_p)) testIPID=p$ip$id/256; 
  if (testConState=="REJ" && testIPID<= 128 && testIPID > 0 && c$history == "")
  {
    ++REJ_count;
    NOTICE([$note=IPIDdetected, 
    $src=c$id$orig_h, $msg="Observed ASCII IP ID values.", 
    $sub="May indicate Covert_tcp usage.",
    $conn=c,
    $identifier=cat(c$id$orig_h)]); 
    }                 
}
 