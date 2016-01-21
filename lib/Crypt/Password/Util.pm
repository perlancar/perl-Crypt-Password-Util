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
                 (?P<header>\$ 2 [ayb]? \$)
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

sub _random_base64_chars {
    state $dummy = do { require Bytes::Random::Secure };

    my $num_chars = shift;

    my $num_bytes = int($num_chars * 3/4) + 1;
    my $res = substr(
        Bytes::Random::Secure::random_bytes_base64($num_bytes), 0, $num_chars);
    $res =~ s/\+/./g;
    #say "D:random_base64_chars=<$res> ($num_chars)";
    return $res;
}

sub crypt {
    my $pass = shift;
    my ($salt, $crypt);

    # on OpenBSD, first try BCRYPT
    if ($^O eq 'openbsd') {
        $salt = sprintf('$2b$%02d$%s', 7, _random_base64_chars(22));
        $crypt = CORE::crypt($pass, $salt);
        return $crypt if 'BCRYPT' eq (crypt_type($crypt) // '');
    } else {
        # otherwise, try SSHA512
        $salt  = sprintf('$6$rounds=%d$%s', 15000, _random_base64_chars(16));
        $crypt = CORE::crypt($pass, $salt);
        return $crypt if 'SSHA512' eq (crypt_type($crypt) // '');
    }

    # next, try MD5-CRYPT
    $salt = sprintf('$1$%s', _random_base64_chars(8));
    $crypt = CORE::crypt($pass, $salt);
    return $crypt if 'MD5-CRYPT' eq (crypt_type($crypt) // '');

    # fallback to CRYPT if failed
    $salt = _random_base64_chars(2);
    $crypt = CORE::crypt($pass, $salt);
    return $crypt if 'CRYPT' eq (crypt_type($crypt) // '');

    die "Can't generate crypt (tried all methods)";
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

Try to create a "reasonably secure" crypt password with the support available
from the system's crypt().

Will first try to create a cost-based crypt, using rounds value that will
approximately take ~10ms (on my PC computer, an Intel Core i5-2400 CPU, that is)
to create. This lets a server verify ~100 passwords per second, which should be
enough for many cases. On OpenBSD, will try BCRYPT with cost=7. On other
systems, will try SSHA512 with rounds=15000.

If the above fails (unsupported by your crypt()), will fallback to MD5-CRYPT
(supported by NetBSD), then CRYPT. Will die if that also fails.


=head1 SEE ALSO

L<Authen::Passphrase> which recognizes more encodings (but currently not SSHA256
and SSHA512).

L<Crypt::Bcrypt::Easy> to generate BCRYPT crypts on systems that do not natively
support it.

L<Crypt::PasswdMD5> to generate MD5-CRYPT crypts on systems that do not natively
support it.

L<Crypt::Password> which also provides a routine to compare a password with a
crypted password.

=cut
