#!/usr/bin/perl
#
# simple root test routine
# Geoff Huston, APNIC
#

while (1) {
  foreach $root ('a'..'m') {
    $rs = $root . ".root-servers.net" ;
    $rs =~ tr/a-z/A-Z/ ;
    $server6 = `dig -6 +short \@$root.root-servers.net. hostname.bind txt chaos`;
    $server6 =~ s/\"//g ;
    chop($server6) ;
    $server4 = `dig -4 +short \@$root.root-servers.net. hostname.bind txt chaos`;
    $server4 =~ s/\"//g ;
    chop($server4) ;
    print("$rs: $server4 (4), $server6 (6)\n") ;

    #
    # generate a lengthy and unique query name
    #
    $val = int(3000000000 + rand(1000000000)) ;
    $name = "DxyMw.WTzEWrfJOe0ppIEfTqP.wgH49qJbmewhFBcJd8a.9euvKw1S1FQFxY2EWWKMIIsP.ObvciODBAjRB2eHZ5zFVEVVNTNmdrBumgI.mQlebyAwnrO79kVpE7lo.Z4U4o4Azh0z4RpDxyMwEl6JUn7ggke42Yya.wecadc341asd.rbHgNH0CshUyZHPy.uNk2Le45btZ2Sndu.JN8Q6GmQlebyAwnrO79kpVplo-_UDP.BQ" . $val . "." ;
    #
    # use 'dig to direct the query to a root server over IPv6
    # set DNSSEC to ON and use an EDNS(0) UDP buffer size of 4096
    #
    $cmd6 =  "dig +dnssec +bufsize=4096 -6 \@$root.root-servers.net. ds $name";
    #
    # collect the response
    #
    @l6 = `$cmd6` ;
    #
    # and print it to stdout
    #
    $lines = join('      ',@l6) ;
    $rs = $root . ".root-servers.net" ;
    $rs =~ tr/a-z/A-Z/ ;
    print("$rs V6\n    $lines\n") ;
    #
    # pace the queries do we are not jamming the root servers
    #
    $val = int(3000000000 + rand(1000000000)) ;
    $name = "DxyMw.WTzEWrfJOe0ppIEfTqP.wgH49qJbmewhFBcJd8a.9euvKw1S1FQFxY2EWWKMIIsP.ObvciODBAjRB2eHZ5zFVEVVNTNmdrBumgI.mQlebyAwnrO79kVpE7lo.Z4U4o4Azh0z4RpDxyMwEl6JUn7ggke42Yya.wecadc341asd.rbHgNH0CshUyZHPy.uNk2Le45btZ2Sndu.JN8Q6GmQlebyAwnrO79kpVplo--TCP.BQ" . $val . "." ;
    $cmd6 =  "dig +dnssec +bufsize=4096 -6 +tcp \@$root.root-servers.net. ds $name";
    @l6 = `$cmd6` ;
    $lines = join('      ',@l6) ;
    $rs = $root . ".root-servers.net" ;
    $rs =~ tr/a-z/A-Z/ ;
    print("$rs V6\n    $lines\n") ;


    # use 'dig to direct the query to a root server over IPv4
    # set DNSSEC to ON and use an EDNS(0) UDP buffer size of 4096
    #
    $val = int(3000000000 + rand(1000000000)) ;
    $name = "DxyMw.WTzEWrfJOe0ppIEfTqP.wgH49qJbmewhFBcJd8a.9euvKw1S1FQFxY2EWWKMIIsP.ObvciODBAjRB2eHZ5zFVEVVNTNmdrBumgI.mQlebyAwnrO79kVpE7lo.Z4U4o4Azh0z4RpDxyMwEl6JUn7ggke42Yya.wecadc341asd.rbHgNH0CshUyZHPy.uNk2Le45btZ2Sndu.JN8Q6GmQlebyAwnrO79kpVplo--UDP.BQ" . $val . "." ;
    $cmd4 =  "dig +dnssec +bufsize=4096 -4 \@$root.root-servers.net. ds $name";
    #
    # collect the response
    #
    @l4 = `$cmd4` ;
    #
    # and print it to stdout
    #
    $lines = join('      ',@l4) ;
    $rs = $root . ".root-servers.net" ;
    $rs =~ tr/a-z/A-Z/ ;
    print("$rs V4\n    $lines\n") ;
    #
    # pace the queries do we are not jamming the root servers
    #
    $val = int(3000000000 + rand(1000000000)) ;
    $name = "DxyMw.WTzEWrfJOe0ppIEfTqP.wgH49qJbmewhFBcJd8a.9euvKw1S1FQFxY2EWWKMIIsP.ObvciODBAjRB2eHZ5zFVEVVNTNmdrBumgI.mQlebyAwnrO79kVpE7lo.Z4U4o4Azh0z4RpDxyMwEl6JUn7ggke42Yya.wecadc341asd.rbHgNH0CshUyZHPy.uNk2Le45btZ2Sndu.JN8Q6GmQlebyAwnrO79kpVplo--TCP.BQ" . $val . "." ;
    $cmd6 =  "dig +dnssec +bufsize=4096 -4 +tcp \@$root.root-servers.net. ds $name";
    @l6 = `$cmd6` ;
    $lines = join('      ',@l6) ;
    $rs = $root . ".root-servers.net" ;
    $rs =~ tr/a-z/A-Z/ ;
    print("$rs V4\n    $lines\n") ;
    }
  sleep(2) ;
  }
