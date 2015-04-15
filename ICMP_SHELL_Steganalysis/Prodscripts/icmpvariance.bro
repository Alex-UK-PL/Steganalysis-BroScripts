@load base/frameworks/notice
@load base/frameworks/sumstats/plugins/variance.bro
#Author : hosom 
#Mail   : 0xhosom@gmail.com
#
#		Copyright (c) 2015, All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without modification,
#     are permitted provided that the following conditions are met:
#
#    Redistributions of source code must retain the above copyright notice,
#     this list of conditions and the following disclaimer.
#
#    Redistributions in binary form must reproduce the above copyright notice, 
#     this list of conditions and the following disclaimer in the documentation
#     and/or other materials
#     provided with the distribution.
#
#    Neither the name of bro-scripts nor the names of its contributors may be used to endorse or promote 
#     products derived from this software without specific prior written #permission.
#
#	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
# 	INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF #MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# 	IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, #SPECIAL, EXEMPLARY, 
#	OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
#	HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
#	ARISING IN ANY WAY OUT OF THE USE OF THIS #SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

module DetectICMPSHell;

export {
	redef enum Notice::Type += {
		## High variance in ICMP connections indicates ICMP shells
		ICMP_High_Variance
	};

	## Tolerance level for variance of ICMP connections from the 
	## same client
	const icmp_variance_threshold = 1.0 &redef;
}

event icmp_sent(c: connection, icmp: icmp_conn)
	{
	SumStats::observe("icmp.shell.variance", [$host=c$id$orig_h], [$num=icmp$len]);
	}

event icmp_echo_request(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string)
	{
	SumStats::observe("icmp.shell.variance", [$host=c$id$orig_h], [$num=|payload|]);
	}

event icmp_echo_reply(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string)
	{
	SumStats::observe("icmp.shell.variance", [$host=c$id$orig_h], [$num=|payload|]);
	}

event icmp_error_message(c: connection, icmp: icmp_conn, code: count, context: icmp_context)
	{
	SumStats::observe("icmp.shell.variance", [$host=c$id$orig_h], [$num=icmp$len]);
	}

event icmp_neighbor_advertisement(c: connection, icmp: icmp_conn, router: bool, solicited: bool, override: bool, tgt: addr, options: icmp6_nd_options)
	{
	SumStats::observe("icmp.shell.variance", [$host=c$id$orig_h], [$num=icmp$len]);
	}

event icmp_neighbor_solicitation(c: connection, icmp: icmp_conn, tgt: addr, options: icmp6_nd_options)
	{
	SumStats::observe("icmp.shell.variance", [$host=c$id$orig_h], [$num=icmp$len]);
	}

event icmp_packet_too_big(c: connection, icmp: icmp_conn, code: count, context: icmp_context)
	{
	SumStats::observe("icmp.shell.variance", [$host=c$id$orig_h], [$num=icmp$len]);
	}

event icmp_parameter_problem(c: connection, icmp: icmp_conn, code: count, context: icmp_context)
	{
	SumStats::observe("icmp.shell.variance", [$host=c$id$orig_h], [$num=icmp$len]);
	}

event icmp_redirect(c: connection, icmp: icmp_conn, tgt: addr, dest: addr, options: icmp6_nd_options)
	{
	SumStats::observe("icmp.shell.variance", [$host=c$id$orig_h], [$num=icmp$len]);
	}

event icmp_router_advertisement(c: connection, icmp: icmp_conn, cur_hop_limit: count, managed: bool, other: bool, home_agent: bool, pref: count, proxy: bool, rsv: count, router_lifetime: interval, reachable_time: interval, retrans_timer: interval, options: icmp6_nd_options)
	{
	SumStats::observe("icmp.shell.variance", [$host=c$id$orig_h], [$num=icmp$len]);
	}

event icmp_router_solicitation(c: connection, icmp: icmp_conn, options: icmp6_nd_options)
	{
	SumStats::observe("icmp.shell.variance", [$host=c$id$orig_h], [$num=icmp$len]);
	}

event icmp_time_exceeded(c: connection, icmp: icmp_conn, code: count, context: icmp_context)
	{
	SumStats::observe("icmp.shell.variance", [$host=c$id$orig_h], [$num=icmp$len]);
	}

event icmp_unreachable(c: connection, icmp: icmp_conn, code: count, context: icmp_context)
	{
	SumStats::observe("icmp.shell.variance", [$host=c$id$orig_h], [$num=icmp$len]);
	}

event bro_init()
	{
	local r1 = SumStats::Reducer($stream="icmp.shell.variance",
								 $apply=set(SumStats::VARIANCE));

	SumStats::create([$name="detect-icmp-shell",
					  $epoch=5mins,
					  $reducers=set(r1),
					  $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
					  	{
					  	return result["icmp.shell.variance"]$variance;
					  	},
					  $threshold=icmp_variance_threshold,
					  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = 
					  	{
					  	NOTICE([$note=ICMP_High_Variance,
					  			$src=key$host,
					  			$msg="Observed high ICMP orig_bytes variance.",
					  			$sub="May indicate an ICMP Shell.",
					  			$identifier=cat(key$host)]);
					  	}]);
	}
