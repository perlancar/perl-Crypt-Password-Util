#!perl

use 5.010;
use strict;
use warnings;

use Crypt::Password::Util qw(looks_like_crypt);
use Test::More 0.98;

ok( looks_like_crypt('$1$$oXYGukVGYa16SN.Pw5vNt/'));
ok( looks_like_crypt('$apr1$x$A8hldSzKARXWgJiwY6zTC.'));
ok( looks_like_crypt('$apr1$12345678$A8hldSzKARXWgJiwY6zTC.'));
ok( looks_like_crypt('$6$12345678$'.("a" x 86)));
ok(!looks_like_crypt('foo'));

done_testing();
