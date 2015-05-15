module seq;
export {
    redef enum Notice::Type += { TCPSEQdetected };  
    global testConState : string = "";
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
  local testIPSEQ =0;
  if ( (is_tcp_port(c$id$resp_p) || is_tcp_port(c$id$orig_p)) && testConState=="REJ" && c$history == "") testIPSEQ= p$tcp$seq/16777216;
 if (testIPSEQ < 128  && testIPSEQ >= 0)
  {
    ++REJ_count;
    NOTICE([$note=TCPSEQdetected, 
    $src=c$id$orig_h, $msg="Observed ASCII TCP SEQ values.", 
    $sub="May indicate Covert_tcp usage.",
    $conn=c,
    $identifier=cat(c$uid)]); 
   }                 
}
