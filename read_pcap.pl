#!/usr/bin/perl
#
# extremely simple tcmdump parser
#
# list of IPv6 root server addresses
#
$| = 1 ;

%roots = (
  "2001:503:ba3e::2:30"=>"A",
  "2001:500:84::b"=>"B",
  "2001:500:2::c"=>"C",
  "2001:500:2d::d"=>"D",
  "2001:500:a8::e"=>"E",
  "2001:500:2f::f"=>"F",
  "2001:500:12::d0d"=>"G",
  "2001:500:1::53"=>"H",
  "2001:7fe::53"=>"I",
  "2001:503:c27::2:30"=>"J",
  "2001:7fd::1"=>"K",
  "2001:500:9f::42"=>"L",
  "2001:dc3::35"=>"M",
  "198.41.0.4"=>"A",
  "192.228.79.201"=>"B",
  "192.33.4.12"=>"C",
  "199.7.91.13"=>"D",
  "192.203.230.10"=>"E",
  "192.5.5.241"=>"F",
  "192.112.36.4"=>"G",
  "198.97.190.53"=>"H",
  "192.36.148.17"=>"I",
  "192.58.128.30"=>"J",
  "193.0.14.129"=>"K",
  "199.7.83.42"=>"L",
  "202.12.27.33"=>"M");

$l = "" ;
while ($lb = <>) {
  chop($lb) ;
  if ($lb =~ /^\s/) {
    $l .= $lb ;
    }

  if (!$l) {
    $l = $lb ;
    next ;
    }

  (@f) = split(/\s/,$l)  ;

  $time = $f[0] ;
  #
  # Fragmented packet - calc the full packet size (payload length + 40)
  # this gets the first packet fragment
  #
  if ($l =~ /Fragment.*\s(\d+)\)\s([a-f0-9\:]+)\s\>.*0\|\d+\)/) {
    $length = $1 ;
    $srv = $2 ;
    $length += 40 ;
    $root = $roots{$srv} ;
    print("***FRAG $root $srv F $length $time\n") ;
    }
  #
  # Truncated packet = calc the full packet size
  #
  elsif ($l =~ /UDP.*\s(\d+)\)\s([a-f0-9\:]+).53\s\>.*\-\|\sq\:/) {
    $length = $1 ;
    $srv = $2 ;
    $length += 40 ;
    $root = $roots{$srv} ;
    print("***TRUNC $root $srv X $length $time\n") ;
    }
  #
  # unfragmented UDP packet
  #
  elsif ($l =~ /UDP.*\s(\d+)\)\s([a-f0-9\:]+).53\s\>/) {
    $length = $1 ;
    $srv = $2 ;
    $length += 40 ;
    $root = $roots{$srv} ;
    print("***UDP $root $srv U $length $time\n") ;
    }
  else { print("$l\n") ; }

  $l = $lb ;
}





