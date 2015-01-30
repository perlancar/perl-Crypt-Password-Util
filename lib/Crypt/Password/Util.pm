package Crypt::Password::Util;

# DATE
# VERSION

use 5.010001;
use strict;
use warnings;

use Exporter;
our @ISA = qw(Exporter);
our @EXPORT_OK = qw(crypt_type looks_like_crypt crypt crypt_detail);

my $b64d = qr![A-Za-z0-9./]!;
my $hexd = qr![0-9a-f]!;

our %CRYPT_TYPES = (
    'MD5-CRYPT' => {
        summary => 'A baroque passphrase scheme based on MD5, designed by Poul-Henning Kamp and originally implemented in FreeBSD',
        re => qr/\A (\$ (?:apr)?1 \$) ($b64d {0,8}) \$ ($b64d {22}) \z/x,
        re_summary => '$1$ or $apr1$ header',
	re_link => 'http://static.usenix.org/event/usenix99/provos/provos_html/node10.html',
    },
    CRYPT => {
        summary => 'Traditional DES crypt',
        re => qr/\A () (..) ($b64d {11}) \z/x,
        re_summary => '11 digit base64 characters',
	re_link => 'http://perldoc.perl.org/functions/crypt.html',
    },
    SSHA256 => {
        summary => 'Salted SHA256, supported by glibc 2.7+',
        re => qr/\A (\$ 5 \$) ($b64d {0,16}) \$ ($b64d {43}) \z/x,
        re_summary => '$5$ header',
	re_link => 'http://en.wikipedia.org/wiki/SHA-2',
    },
    SSHA512 => {
        summary => 'Salted SHA512, supported by glibc 2.7+',
        re => qr/\A (\$ 6 \$) ($b64d {0,16}) \$ ($b64d {86}) \z/x,
        re_summary => '$6$ header',
	re_link => 'http://en.wikipedia.org/wiki/SHA-2',
    },
    BCRYPT => {
        summary => 'Passphrase scheme based on Blowfish, designed by Niels Provos and David Mazieres for OpenBSD',
        re => qr/\A (\$ 2a? \$ \d+) \$ ($b64d {22}) ($b64d {31}) \z/x,
        re_summary => '$2$ or $2a$header followed by 22 base64-digits salt and 31 digits hash',
	re_link => 'https://www.usenix.org/legacy/event/usenix99/provos/provos_html/',
    },
    'PLAIN-MD5' => {
        summary => 'Unsalted MD5 hash, popular with PHP web applications',
        re => qr/\A () () ($hexd {32}) \z/x,
        re_summary => '32 digits of hex characters',
	re_link => 'http://en.wikipedia.org/wiki/MD5',
    },
);

sub crypt_type {
    my $crypt = shift;
    for my $type (keys %CRYPT_TYPES) {
        return $type if $crypt =~ $CRYPT_TYPES{$type}{re};
    }
    return undef;
}

sub crypt_detail {
    my $crypt = shift;
    my $type = crypt_type($crypt);
    return $type if !defined $type;

    my ($header, $salt, $hash) = ($crypt =~ $CRYPT_TYPES{$type}{re});
    return "Type: $type, Header: $header, Salt: $salt, Hash: $hash";
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

 use Crypt::Password::Util qw(crypt_type looks_like_crypt crypt);

 say crypt_type('62F4a6/89.12z');                    # CRYPT
 say crypt_type('$1$$...');                          # MD5-CRYPT
 say crypt_type('$apr1$4DdvgCFk$...');               # MD5-CRYPT
 say crypt_type('$5$4DdvgCFk$...');                  # SSHA256
 say crypt_type('$6$4DdvgCFk$...');                  # SSHA512
 say crypt_type('1a1dc91c907325c69271ddf0c944bc72'); # PLAIN-MD5
 say crypt_type('foo');                              # undef

 say crypt_detail('62F4a6/89.12z');
  # Type: CRYPT, Header: , Salt: 62, Hash: F4a6/89.12z
 say crypt_detail('$1$$oXYGukVGYa16SN.Pw5vNt/');
  # Type: MD5-CRYPT, Header: $1$, Salt: , Hash: oXYGukVGYa16SN.Pw5vNt/
 say crypt_detail('$5$123456789$'.("a" x 43));
  # Type: SSHA256, Header: $5$, Salt: 123456789, Hash: a...
 say crypt_detail('$6$12345678$'.("a" x 86));
  # Type: SSHA512, Header: $6$, Salt: 12345678, Hash: a...
 say crypt_detail('1a1dc91c907325c69271ddf0c944bc72');
  # Type: PLAIN-MD5, Header: , Salt: , Hash: 1a1dc91c907325c69271ddf0c944bc72
 say crypt_detail('foo');
  # undef

 say looks_like_crypt('62F4a6/89.12z');   # 1
 say looks_like_crypt('foo');             # 0

 say crypt('pass'); # automatically choose the appropriate type and salt


=head1 DESCRIPTION

 Crypt::Password::Util facilitates the generation and recognition of unix
 passwords as found in /etc/shadow on Unix/Linux systems and /etc/master.passwd
 on BSD systems.  When using crypt(), it is possible several methods will be
 attempted before returning a result.  This is done to insure that your system
 supports the selected hash type.

=head1 FUNCTIONS

=head2 crypt_type($str) => STR

Return crypt type, or undef if C<$str> does not look like a crypted password.
Currently known types:

# CODE: require Crypt::Password::Util; my $types = \%Crypt::Password::Util::CRYPT_TYPES; print "=over\n\n"; for my $type (sort keys %$types) { print "=item * $type\n\n$types->{$type}{summary}.\n\nRecognized by: $types->{$type}{re_summary}.\n\nMore info: L<$types->{$type}{re_link}>\n\n" } print "=back\n\n";

=head2 crypt_detail($str) => STR

Return crypt type, header, salt and hash values in a string, or undef if
C<$str> does not look like a crypted password.

=head2 looks_like_crypt($str) => BOOL

Return true if C<$str> looks like a crypted password.

=head2 crypt($str) => STR

Like Perl's crypt(), but automatically choose the appropriate crypt type and
random salt. Will first choose SSHA512 with 64-bit random salt. If not supported
by system, fall back to MD5-CRYPT with 32-bit random salt. If that is not
supported, fall back to CRYPT.


=head1 SEE ALSO

L<Authen::Passphrase> which recognizes more encodings (but currently not SSHA256
and SSHA512).

=cut
