package Crypt::Password::Util;

# DATE
# VERSION

use 5.010001;
use strict;
use warnings;

use Exporter;
our @ISA = qw(Exporter);
our @EXPORT_OK = qw(crypt_type looks_like_crypt crypt);

my $b64d = qr![A-Za-z0-9./]!;
my $hexd = qr![0-9a-f]!;

our %CRYPT_TYPES = (
    'MD5-CRYPT' => {
        summary => 'A baroque passphrase scheme based on MD5, designed by Poul-Henning Kamp and originally implemented in FreeBSD',
        re => qr/\A
                 (?P<header>\$ (?:apr)?1 \$)
                 (?P<salt>$b64d {0,8}) \$
                 (?P<hash>$b64d {22}) \z/x,
        re_summary => '$1$ or $apr1$ header',
        link => 'http://static.usenix.org/event/usenix99/provos/provos_html/node10.html',
    },
    CRYPT => {
        summary => 'Traditional DES crypt',
        re => qr/\A
                 (?P<salt>$b64d {2} | \$\$) # $$ is not accepted as salt, but we see crypts using those in the wild
                 (?P<hash>$b64d {11}) \z/x,
        re_summary => '11 digit base64 characters',
        link => 'http://perldoc.perl.org/functions/crypt.html',
    },
    'EXT-DES' => {
        summary => 'Extended DES crypt',
        re => qr/\A
                 (?P<salt>_ $b64d {8} )
                 (?P<hash>$b64d {11}) \z/x,
        re_summary => 'underscore followed by 19 digit base64 characters',
        link => 'https://en.wikipedia.org/wiki/Crypt_%28C%29#BSDi_extended_DES-based_scheme',
    },
    SSHA256 => {
        summary => 'Salted SHA256, supported by glibc 2.7+',
        re => qr/\A
                 (?P<header>\$ 5 \$)
                 (?P<salt> (?:rounds=[1-9][0-9]{3,8}\$)? $b64d {0,16}) \$
                 (?P<hash>$b64d {43}) \z/x,
        re_summary => '$5$ header',
        link => 'http://en.wikipedia.org/wiki/SHA-2',
    },
    SSHA512 => {
        summary => 'Salted SHA512, supported by glibc 2.7+',
        re => qr/\A
                 (?P<header>\$ 6 \$)
                 (?P<salt> (?:rounds=[1-9][0-9]{3,8}\$)? $b64d {0,16}) \$
                 (?P<hash>$b64d {86}) \z/x,
        re_summary => '$6$ header',
        link => 'http://en.wikipedia.org/wiki/SHA-2',
    },
    BCRYPT => {
        summary => 'Passphrase scheme based on Blowfish, designed by Niels Provos and David Mazieres for OpenBSD',
        re => qr/\A
                 (?P<header>\$ 2a? \$)
                 (?P<cost>\d+) \$
                 (?P<salt>$b64d {22})
                 (?P<hash>$b64d {31}) \z/x,
        re_summary => '$2$ or $2a$ header followed by cost, followed by 22 base64-digits salt and 31 digits hash',
        link => 'https://www.usenix.org/legacy/event/usenix99/provos/provos_html/',
    },
    'PLAIN-MD5' => {
        summary => 'Unsalted MD5 hash, popular with PHP web applications',
        re => qr/\A (?P<hash>$hexd {32}) \z/x,
        re_summary => '32 digits of hex characters',
        link => 'http://en.wikipedia.org/wiki/MD5',
    },
);

sub crypt_type {
    my $crypt = shift;
    my $detail = shift;

    for my $type (keys %CRYPT_TYPES) {
        if ($crypt =~ $CRYPT_TYPES{$type}{re}) {
            if ($detail) {
                my $res = {%+};
                $res->{type} = $type;
                return $res;
            } else {
                return $type;
            }
        }
    }
    return undef;
}

sub looks_like_crypt { !!crypt_type($_[0]) }

sub crypt {
    require UUID::Random::Patch::UseMRS;
    require Digest::MD5;

    my $pass = shift;
    my ($salt, $crypt);

    # first use SSHA512
    $salt  = substr(Digest::MD5::md5_base64(UUID::Random::generate()), 0, 16);
    $salt =~ tr/\+/./;
    $crypt = CORE::crypt($pass, '$6$'.$salt.'$');
    #say "D:salt=$salt, crypt=$crypt";
    return $crypt if (crypt_type($crypt)//"") eq 'SSHA512';

    # fallback to MD5-CRYPT if failed
    $salt = substr($salt, 0, 8);
    $crypt = CORE::crypt($pass, '$1$'.$salt.'$');
    return $crypt if (crypt_type($crypt)//"") eq 'MD5-CRYPT';

    # fallback to CRYPT if failed
    $salt = substr($salt, 0, 2);
    CORE::crypt($pass, $salt);
}

1;
# ABSTRACT: Crypt password utilities

=head1 SYNOPSIS

 use Crypt::Password::Util qw(
     crypt
     looks_like_crypt
     crypt_type
 );

Generating crypted password:

 say crypt('pass'); # automatically choose the appropriate type and salt

Recognizing whether a string is a crypted password:

 # return yes/no
 say looks_like_crypt('62F4a6/89.12z');   # 1
 say looks_like_crypt('foo');             # 0

 # return the crypt type
 say crypt_type('62F4a6/89.12z');                    # CRYPT
 say crypt_type('$1$$...');                          # MD5-CRYPT
 say crypt_type('$apr1$4DdvgCFk$...');               # MD5-CRYPT
 say crypt_type('$5$4DdvgCFk$...');                  # SSHA256
 say crypt_type('$6$4DdvgCFk$...');                  # SSHA512
 say crypt_type('1a1dc91c907325c69271ddf0c944bc72'); # PLAIN-MD5
 say crypt_type('$2a$08$TTSynMjJTrXiv3qEZFyM1.H9tjv71i57p2r63QEJe/2p0p/m1GIy2'); # BCRYPT
 say crypt_type('foo');                              # undef

 # return detailed information
 my $res = crypt_type('$1$$oXYGukVGYa16SN.Pw5vNt/', 1);
 # => {type=>'MD5-CRYPT', header=>'$1$', salt=>'', hash=>'oXYGukVGYa16SN.Pw5vNt/'}
 $res = crypt_type('foo', 1);
 # => undef


=head1 DESCRIPTION

Crypt::Password::Util provides routines to: 1) generate crypted password; 2)
recognition of whether a string is a crypted password or not, and its crypt
type.

It recognizes several types of crypt methods:

# CODE: require Crypt::Password::Util; my $types = \%Crypt::Password::Util::CRYPT_TYPES; print "=over\n\n"; for my $type (sort keys %$types) { print "=item * $type\n\n$types->{$type}{summary}.\n\nRecognized by: $types->{$type}{re_summary}.\n\nMore info: L<$types->{$type}{link}>\n\n" } print "=back\n\n";


=head1 FUNCTIONS

=head2 looks_like_crypt($str) => bool

Return true if C<$str> looks like a crypted password. If you want more
information instead of just a yes/no, use C<crypt_type()>.

=head2 crypt_type($str[, $detail]) => str|hash

Return crypt type, or undef if C<$str> does not look like a crypted password.
Currently known types:

If C<$detail> is set to true, will return a hashref of information instead. This
include C<type>, as well as the parsed header, salt, etc.

=head2 crypt($str) => str

Crypt password. Will first choose SSHA512 with 64-bit random salt. If not
supported by system, fall back to MD5-CRYPT with 32-bit random salt. If that is
not supported, fall back to CRYPT (traditional DES).


=head1 SEE ALSO

L<Authen::Passphrase> which recognizes more encodings (but currently not SSHA256
and SSHA512).

L<Crypt::Bcrypt::Easy> to generate BCRYPT crypts.

L<Crypt::PasswdMD5> to generate MD5-CRYPT crypts.

L<Crypt::Password> which also provides a routine to compare a password with a
crypted password.

=cut
