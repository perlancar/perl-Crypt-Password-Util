package Crypt::Password::Util;

use 5.010;
use strict;
use warnings;

# VERSION

use Exporter;
our @ISA = qw(Exporter);
our @EXPORT_OK = qw(crypt_type looks_like_crypt crypt);

my $b64d = qr![A-Za-z0-9./]!;
my $hexd = qr![0-9a-f]!;

sub crypt_type {
    local $_ = shift;

    return "CRYPT"     if /\A .. $b64d {11} \z/ox;

    return "MD5-CRYPT" if /\A \$ (?:apr)?1 \$ $b64d {0,8} \$ $b64d {22} \z/ox;

    # salted SHA256, supported by glibc 2.7+
    return "SSHA256"   if /\A \$ 5 \$ $b64d {0,16} \$ $b64d {43} \z/ox;

    # salted SHA512, supported by glibc 2.7+
    return "SSHA512"   if /\A \$ 6 \$ $b64d {0,16} \$ $b64d {86} \z/ox;

    return "PLAIN-MD5" if /\A $hexd {32} \z/ox;

    return undef;
}

sub looks_like_crypt { !!crypt_type($_[0]) }

sub crypt {
    require UUID::Random;
    require Digest::MD5;

    my $pass = shift;
    my ($salt, $crypt);

    # first use SSHA512
    $salt  = substr(Digest::MD5::md5_base64(UUID::Random::generate()), 0, 16);
    $crypt = CORE::crypt($pass, '$6$'.$salt.'$');
    return $crypt if crypt_type($crypt) eq 'SSHA512';

    # fallback to MD5-CRYPT if failed
    $salt = substr($salt, 0, 8);
    $crypt = CORE::crypt($pass, '$1$'.$salt.'$');
    return $crypt if crypt_type($crypt) eq 'MD5-CRYPT';

    # fallback to CRYPT if failed
    $salt = substr($salt, 0, 2);
    CORE::crypt($pass, $salt);
}

1;
# ABSTRACT: Crypt password utilities

=head1 SYNOPSIS

 use Crypt::Password::Util qw(crypt_type looks_like_crypt crypt);

 say crypt_type('62F4a6/89.12z');                    # CRYPT
 say crypt_type('$1$$...');                          # MD5-CRYPT
 say crypt_type('$apr1$4DdvgCFk$...');               # MD5-CRYPT
 say crypt_type('$5$4DdvgCFk$...');                  # SSHA256
 say crypt_type('$6$4DdvgCFk$...');                  # SSHA512
 say crypt_type('1a1dc91c907325c69271ddf0c944bc72'); # PLAIN-MD5
 say crypt_type('foo');                              # undef

 say looks_like_crypt('62F4a6/89.12z');   # 1
 say looks_like_crypt('foo');             # 0

 say crypt('pass'); # automatically choose the appropriate type and salt


=head1 FUNCTIONS

=head2 crypt_type($str) => STR

Return crypt type, or undef if C<$str> does not look like a crypted password.
Currently known types: CRYPT (traditional DES crypt), MD5-CRYPT (including
Apache variant), SSHA256 (salted SHA256), SSHA512 (salted SHA512), and
PLAIN-MD5.

=head2 looks_like_crypt($str) => BOOL

Return true if C<$str> looks like a crypted password.

=head2 crypt($str) => STR

Like Perl's crypt(), but automatically choose the appropriate crypt type and
random salt. Will first choose SSHA512 with 64-bit random salt. If not supported
by system, fall back to MD5-CRYPT with 32-bit random salt. If that is not
supported, fall back to CRYPT.

=cut
