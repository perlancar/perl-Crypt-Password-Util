#!perl

use 5.010;
use strict;
use warnings;

use Crypt::Password::Util qw(crypt_type looks_like_crypt crypt);
use Test::More 0.98;

is( crypt_type('$$.Pw5vNt/...'), "CRYPT");
is( crypt_type('$1$$oXYGukVGYa16SN.Pw5vNt/'), "MD5-CRYPT");
is( crypt_type('$apr1$x$A8hldSzKARXWgJiwY6zTC.'), "MD5-CRYPT");
is( crypt_type('$apr1$12345678$A8hldSzKARXWgJiwY6zTC.'), "MD5-CRYPT");
is( crypt_type('$5$123456789$'.("a" x 43)), "SSHA256");
is( crypt_type('$6$12345678$'.("a" x 86)), "SSHA512");
is( crypt_type('1a1dc91c907325c69271ddf0c944bc72'), "PLAIN-MD5");
ok(!crypt_type('foo'));

ok( looks_like_crypt('$6$12345678$'.("a" x 86)));
ok(!looks_like_crypt('foo'));

# XXX more sophisticated testing
ok(crypt_type(crypt("foo")), "crypt() succeeds");

done_testing();
