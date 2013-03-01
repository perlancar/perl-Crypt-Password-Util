#!perl

use 5.010;
use strict;
use warnings;

use Config;
use Crypt::Password::Util qw(crypt_type looks_like_crypt crypt);
use Sort::Versions;
use Test::More 0.98;

is( crypt_type('$$.Pw5vNt/...'), "CRYPT");
is( crypt_type('$1$$oXYGukVGYa16SN.Pw5vNt/'), "MD5-CRYPT");
is( crypt_type('$apr1$x$A8hldSzKARXWgJiwY6zTC.'), "MD5-CRYPT");
is( crypt_type('$apr1$12345678$A8hldSzKARXWgJiwY6zTC.'), "MD5-CRYPT");
is( crypt_type('$5$123456789$'.("a" x 43)), "SSHA256");
is( crypt_type('$6$12345678$'.("a" x 86)), "SSHA512");
is( crypt_type('1a1dc91c907325c69271ddf0c944bc72'), "PLAIN-MD5");
is( crypt_type('$2a$08$TTSynMjJTrXiv3qEZFyM1.H9tjv71i57p2r63QEJe/2p0p/m1GIy2'), "BCRYPT");
ok(!crypt_type('foo'));

ok( looks_like_crypt('$6$12345678$'.("a" x 86)));
ok(!looks_like_crypt('foo'));

ok(crypt_type(crypt("foo")), "crypt() succeeds");
if ($Config{gnulibc_version} &&
        versioncmp("v$Config{gnulibc_version}", "v2.7") >= 0) {
    note "we are running under glibc 2.7+, SSHA512 should be available";
    like(crypt("foo"), qr/^\$6\$/, "crypt() produces SSHA512");
} else {
    note "can't detect glibc 2.7+, skipping SSHA512 test";
}

done_testing();
